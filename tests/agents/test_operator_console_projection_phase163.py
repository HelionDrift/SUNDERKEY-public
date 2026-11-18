"""Phase 163 operator console projection contract coverage."""

from __future__ import annotations

import copy
import json
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path

import sunderkey

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from sunderkey.operator_console_projection import (
    NO_EFFECTS,
    ApprovalSummary,
    BlockerSummary,
    BudgetSnapshot,
    Counter,
    CoverageSnapshot,
    GraphChangeSummary,
    MissionProjectionInput,
    MissionState,
    OperatorConsoleError,
    OperatorConsoleProjection,
    OperatorIntentRequest,
    ViewRole,
    WorkerSummary,
    build_operator_console_projection,
    build_operator_intent_request,
    canonical_json,
    parse_operator_console_document,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "registry" / "schemas" / "operator-console-contract-v1.schema.json"
FILES = (
    ROOT / "src" / "sunderkey" / "operator_console_projection.py",
    Path(__file__),
    SCHEMA,
    ROOT / "docs" / "operator-console-projection.md",
)
DIGESTS = tuple("sha256:" + character * 64 for character in "0123456789abcdef")


class OperatorConsoleProjectionPhase163Tests(unittest.TestCase):
    def test_public_package_exports_are_available(self) -> None:
        self.assertIs(
            sunderkey.build_operator_console_projection,
            build_operator_console_projection,
        )
        self.assertIs(
            sunderkey.build_operator_intent_request,
            build_operator_intent_request,
        )

    def counter(self, consumed: int = 1, limit: int = 10) -> Counter:
        return Counter(consumed, limit)

    def source(self, **changes: object) -> MissionProjectionInput:
        values: dict[str, object] = {
            "assessment_ref": "assessmentref:mission-001",
            "assessment_version": 9,
            "mission_state": "running",
            "observed_at": "2026-09-20T12:00:00Z",
            "scope_sha256": DIGESTS[0],
            "schedule_sha256": DIGESTS[1],
            "status_sha256": DIGESTS[2],
            "health": "degraded",
            "coverage": CoverageSnapshot(10, 3, 2, 1, 4),
            "budget": BudgetSnapshot(
                requests=self.counter(100, 1000),
                cost_units=self.counter(20, 100),
                tokens=self.counter(300, 10000),
                tool_calls=self.counter(4, 50),
                worker_minutes=self.counter(8, 120),
                storage_bytes=self.counter(1024, 1_000_000),
            ),
            "workers": (
                WorkerSummary(
                    "workerref:worker-02",
                    "AOE-GA-D01-S02",
                    "pending",
                    "healthy",
                    None,
                    "2026-09-20T11:59:58Z",
                ),
                WorkerSummary(
                    "workerref:worker-01",
                    "AOE-GA-D01-S01",
                    "running",
                    "degraded",
                    "taskref:task-01",
                    "2026-09-20T11:59:59Z",
                ),
            ),
            "approvals": (
                ApprovalSummary(
                    "approvalref:approval-01",
                    "safe_probe",
                    "R1",
                    "pending",
                    "2026-09-20T13:00:00Z",
                ),
            ),
            "blockers": (
                BlockerSummary(
                    "blocker.rate-budget",
                    "rate_budget_low",
                    "warning",
                    "Target request budget is nearing its limit.",
                    "assessment_operator",
                ),
            ),
            "graph_changes": (
                GraphChangeSummary(
                    "graphref:delta-01",
                    2,
                    1,
                    3,
                    1,
                    "2026-09-20T11:59:50Z",
                ),
            ),
            "finding_refs": ("findingref:finding-02", "findingref:finding-01"),
            "evidence_refs": ("evidref:evidence-01",),
            "report_refs": ("reportref:report-01",),
            "emergency_stop_recorded": False,
        }
        values.update(changes)
        return MissionProjectionInput(**values)

    def test_all_roles_are_deterministic_and_round_trip(self) -> None:
        source = self.source()
        for role in ViewRole:
            with self.subTest(role=role):
                first = build_operator_console_projection(source, role)
                second = build_operator_console_projection(source, role)
                self.assertEqual(first, second)
                document = canonical_json(first.to_dict())
                parsed = parse_operator_console_document(document)
                self.assertIsInstance(parsed, OperatorConsoleProjection)
                self.assertEqual(parsed.to_dict(), first.to_dict())
                self.assertEqual(first.to_dict()["no_effects"], NO_EFFECTS)

    def test_role_views_are_minimized_and_controls_are_not_authority(self) -> None:
        source = self.source()
        executive_view = build_operator_console_projection(source, "executive_observer")
        executive = executive_view.to_dict()
        self.assertEqual(executive_view.source.workers, ())
        self.assertEqual(executive_view.source.approvals, ())
        self.assertEqual(executive_view.source.finding_refs, ())
        self.assertEqual(executive["source"]["workers"], [])
        self.assertEqual(executive["source"]["approvals"], [])
        self.assertEqual(executive["source"]["finding_refs"], [])
        self.assertEqual(executive["available_intents"], [])

        assurance = build_operator_console_projection(source, "independent_assurance")
        self.assertNotIn("controls", assurance.visible_sections)
        self.assertEqual(assurance.available_intents, ())

        control = build_operator_console_projection(source, "independent_control")
        self.assertIn("controls", control.visible_sections)
        self.assertIn("request_emergency_stop", control.to_dict()["available_intents"])
        self.assertTrue(control.controls_require_external_authorization)

    def test_state_controls_are_display_hints_only(self) -> None:
        paused = build_operator_console_projection(
            self.source(mission_state=MissionState.PAUSED),
            "assessment_operator",
        ).to_dict()
        self.assertIn("request_resume", paused["available_intents"])
        self.assertNotIn("request_pause", paused["available_intents"])

        completed = build_operator_console_projection(
            self.source(mission_state=MissionState.COMPLETED),
            "incident_responder",
        ).to_dict()
        self.assertNotIn("request_emergency_stop", completed["available_intents"])

    def test_intent_request_is_content_addressed_and_has_no_effect(self) -> None:
        request = build_operator_intent_request(
            assessment_ref="assessmentref:mission-001",
            expected_assessment_version=9,
            intent_kind="request_emergency_stop",
            principal_id="principal.operator-01",
            requested_at="2026-09-20T12:01:00Z",
            idempotency_key="idem:emergency-stop-000001",
            rationale="Observed target health degradation.",
        )
        self.assertEqual(request.effect, "none")
        self.assertEqual(request.authorization_status, "external_required")
        parsed = parse_operator_console_document(canonical_json(request.to_dict()))
        self.assertIsInstance(parsed, OperatorIntentRequest)
        self.assertEqual(parsed, request)

    def test_budget_coverage_and_stop_invariants_fail_closed(self) -> None:
        with self.assertRaisesRegex(OperatorConsoleError, "exceeds limit"):
            Counter(11, 10)
        with self.assertRaisesRegex(OperatorConsoleError, "do not equal"):
            CoverageSnapshot(10, 1, 1, 1, 1)
        with self.assertRaisesRegex(OperatorConsoleError, "cannot be ready or running"):
            self.source(emergency_stop_recorded=True)

    def test_duplicate_references_and_secret_text_fail_closed(self) -> None:
        with self.assertRaisesRegex(OperatorConsoleError, "duplicates"):
            self.source(finding_refs=("findingref:finding-01", "findingref:finding-01"))
        with self.assertRaisesRegex(OperatorConsoleError, "prohibited content"):
            BlockerSummary(
                "blocker.secret",
                "bad_detail",
                "critical",
                "api_key=do-not-display-this-value",
                "assessment_operator",
            )
        with self.assertRaisesRegex(OperatorConsoleError, "prohibited content"):
            build_operator_intent_request(
                assessment_ref="assessmentref:mission-001",
                expected_assessment_version=9,
                intent_kind="request_cancel",
                principal_id="principal.operator-01",
                requested_at="2026-09-20T12:01:00Z",
                idempotency_key="idem:cancel-assessment-0001",
                rationale="authorization: Bearer should-not-be-here",
            )

    def test_tampering_noncanonical_input_and_unknown_kind_fail_closed(self) -> None:
        document = build_operator_console_projection(self.source(), "assessment_operator").to_dict()
        document["source"]["assessment_version"] = 10
        with self.assertRaisesRegex(OperatorConsoleError, "identity"):
            OperatorConsoleProjection.from_dict(document)
        with self.assertRaisesRegex(OperatorConsoleError, "not canonical"):
            parse_operator_console_document(json.dumps(document))
        with self.assertRaisesRegex(OperatorConsoleError, "unknown"):
            parse_operator_console_document(canonical_json({"schema_version": 1}))

    def test_derived_values_and_frozen_contracts_fail_closed(self) -> None:
        counter = self.counter(2, 5)
        raw = counter.to_dict()
        raw["remaining"] = 4
        with self.assertRaisesRegex(OperatorConsoleError, "not derived"):
            Counter.from_dict(raw)
        with self.assertRaises(FrozenInstanceError):
            counter.limit = 20  # type: ignore[misc]

    def test_schema_accepts_both_documents_and_rejects_mutation(self) -> None:
        if Draft202012Validator is None:
            self.skipTest("jsonschema is not installed")
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema)
        projection = build_operator_console_projection(
            self.source(), "assessment_operator"
        ).to_dict()
        intent = build_operator_intent_request(
            assessment_ref="assessmentref:mission-001",
            expected_assessment_version=9,
            intent_kind="request_pause",
            principal_id="principal.operator-01",
            requested_at="2026-09-20T12:01:00Z",
            idempotency_key="idem:pause-assessment-0001",
            rationale="Operator requested a controlled pause.",
        ).to_dict()
        validator.validate(projection)
        validator.validate(intent)
        mutated = copy.deepcopy(projection)
        mutated["runtime_effect"] = "mission_changed"
        self.assertTrue(list(validator.iter_errors(mutated)))

    def test_artifacts_have_no_markers_or_unicode_dashes(self) -> None:
        markers = (
            "gen" + "erated by",
            "writ" + "ten by ai",
            "as an " + "ai",
            "chat" + "gpt",
            "code" + "x",
            "clau" + "de",
            "gemi" + "ni",
            "co-auth" + "ored-by",
        )
        for path in FILES:
            with self.subTest(path=path.name):
                text = path.read_text(encoding="utf-8")
                lowered = text.lower()
                self.assertNotIn("\u2013", text)
                self.assertNotIn("\u2014", text)
                for marker in markers:
                    self.assertNotIn(marker, lowered)


if __name__ == "__main__":
    unittest.main()

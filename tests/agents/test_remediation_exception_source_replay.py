"""Exception metadata cannot predate or escape its exact original plan."""

from __future__ import annotations

import contextlib
import copy
import io
import unittest
from unittest.mock import patch

from sunderkey.cli import build_parser
from sunderkey.errors import SunderkeyError
from sunderkey.remediation_case_review import (
    RemediationCaseReviewError,
    build_remediation_case_review,
)
from sunderkey.remediation_validation_contracts import (
    ClosureDisposition,
    GateDisposition,
    RemediationValidationError,
    verify_closure_decision,
    verify_risk_exception,
)
from tests.agents.test_remediation_case_review_io import request
from tests.agents.test_remediation_validation_contracts_phase168 import (
    HASHES,
    _context,
    _decide,
    _exception,
    _observation,
    _plan,
    _retest,
)


class RemediationExceptionSourceReplayTests(unittest.TestCase):
    def test_exact_sources_are_unchanged_without_currentness_or_approval_effect(self) -> None:
        plan = _plan()
        exception = _exception(plan)
        before = copy.deepcopy((plan.to_dict(), exception.to_dict()))
        verify_risk_exception(plan, exception)
        self.assertEqual((plan.to_dict(), exception.to_dict()), before)
        self.assertTrue(all(value == "none" for value in exception.effects.values()))

    def test_approval_cannot_precede_plan_creation_or_follow_plan_expiry(self) -> None:
        plan = _plan()
        for approved_at in ("2026-09-20T10:04:59Z", "2026-09-21T09:30:01Z"):
            exception = _exception(
                plan, approved_at=approved_at, expires_at="2026-09-22T09:00:00Z"
            )
            with self.subTest(approved_at=approved_at):
                with self.assertRaisesRegex(RemediationValidationError, "source plan window"):
                    verify_risk_exception(plan, exception)

    def test_source_only_window_preserves_inclusive_historical_endpoints(self) -> None:
        plan = _plan()
        for approved_at in (plan.created_at, plan.expires_at):
            verify_risk_exception(
                plan,
                _exception(plan, approved_at=approved_at, expires_at="2026-09-22T09:00:00Z"),
            )

    def test_context_plan_and_unknown_item_or_control_substitution_fail_closed(self) -> None:
        plan = _plan()
        for changes in (
            {"context_sha256": HASHES[15]},
            {"remediation_plan_sha256": HASHES[15]},
            {"context_id": "RMC-" + "0" * 32},
            {"remediation_plan_id": "RMP-" + "0" * 32},
            {"item_refs": ("itemref:absent",)},
            {"control_refs": ("controlref:absent",)},
        ):
            with self.subTest(changes=changes):
                with self.assertRaises(RemediationValidationError):
                    verify_risk_exception(plan, _exception(plan, **changes))

    def test_partial_metadata_is_not_promoted_to_complete_exception_coverage(self) -> None:
        plan = _plan()
        exception = _exception(plan, item_refs=(plan.items[0].item_ref,))
        verify_risk_exception(plan, exception)
        retest = _retest(plan)
        failed = _observation(plan, retest, disposition=GateDisposition.FAIL)
        with self.assertRaisesRegex(RemediationValidationError, "coverage"):
            _decide(plan, retest, failed, exception=exception)

    def test_expired_metadata_remains_source_valid_and_advisory(self) -> None:
        context = _context()
        plan = _plan(context)
        exception = _exception(plan, expires_at="2026-09-20T12:00:00Z")
        verify_risk_exception(plan, exception)
        result = build_remediation_case_review(
            context,
            plan,
            targets=(),
            delivery_observations=(),
            as_of="2026-09-20T12:40:00Z",
            exception=exception,
        )
        self.assertFalse(result["exception_summary"]["declared_exception_window_open"])
        self.assertFalse(result["exception_summary"]["effective_risk_acceptance_verified"])
        self.assertEqual(result["case_status"], "review_required")

    def test_mutated_typed_plan_and_exception_are_reconstructed(self) -> None:
        for source, attribute in (("plan", "proposed_by"), ("exception", "approved_by")):
            plan = _plan()
            exception = _exception(plan)
            record = plan if source == "plan" else exception
            object.__setattr__(record, attribute, "principalref:substituted")
            with self.subTest(source=source):
                with self.assertRaisesRegex(RemediationValidationError, "content address"):
                    verify_risk_exception(plan, exception)

    def test_untyped_sources_fail_closed(self) -> None:
        plan = _plan()
        for sources in ((object(), _exception(plan)), (plan, object())):
            with self.assertRaises(RemediationValidationError):
                verify_risk_exception(*sources)

    def test_full_pass_does_not_silently_ignore_an_invalid_supplied_exception(self) -> None:
        plan = _plan()
        retest = _retest(plan)
        observed = _observation(plan, retest)
        decision = _decide(plan, retest, observed)
        self.assertEqual(decision.disposition, ClosureDisposition.CLOSED_NONQUALIFIED)
        for exception in (
            _exception(plan, approved_at="2026-09-20T09:00:00Z"),
            _exception(plan, context_sha256=HASHES[15]),
        ):
            with self.assertRaises(RemediationValidationError):
                _decide(plan, retest, observed, exception=exception)
            with self.assertRaises(RemediationValidationError):
                verify_closure_decision(plan, retest, observed, decision, exception=exception)
        valid = _exception(plan)
        self.assertEqual(_decide(plan, retest, observed, exception=valid), decision)

    def test_exception_based_closure_and_planning_only_review_reject_early_approval(self) -> None:
        context = _context()
        plan = _plan(context)
        retest = _retest(plan)
        failed = _observation(plan, retest, disposition=GateDisposition.FAIL)
        exception = _exception(plan, approved_at="2026-09-20T09:00:00Z")
        with self.assertRaisesRegex(RemediationValidationError, "source plan window"):
            _decide(plan, retest, failed, exception=exception)
        with self.assertRaisesRegex(RemediationCaseReviewError, "source plan window"):
            build_remediation_case_review(
                context,
                plan,
                targets=(),
                delivery_observations=(),
                as_of="2026-09-20T12:40:00Z",
                exception=exception,
            )

    def test_cli_rejects_impossible_exception_before_printing_a_review(self) -> None:
        raw = request()
        raw["exception"] = _exception(_plan(), approved_at="2026-09-20T09:00:00Z").to_dict()
        args = build_parser().parse_args(["remediation-case-review", "--input", "source.json"])
        stdout = io.StringIO()
        with patch("sunderkey.cli.load_remediation_case_request", return_value=raw):
            with contextlib.redirect_stdout(stdout):
                with self.assertRaisesRegex(SunderkeyError, "source plan window"):
                    args.handler(args)
        self.assertEqual(stdout.getvalue(), "")

    def test_package_exports_source_only_verifier(self) -> None:
        import sunderkey

        self.assertIs(sunderkey.verify_remediation_risk_exception, verify_risk_exception)


if __name__ == "__main__":
    unittest.main()

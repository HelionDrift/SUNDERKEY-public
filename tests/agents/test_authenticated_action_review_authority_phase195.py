"""Phase194 and Phase195 current-review authority integration tests."""

from __future__ import annotations

import unittest
from dataclasses import replace

from sunderkey.action_resolution import (
    ActionResolutionError,
    _verify_current_expert_review_closure,
)
from sunderkey.authenticated_action_review_authority import (
    AuthenticatedExpertReviewClosureVerifierAdapter,
)

from . import test_authenticated_expert_review_phase194 as phase194_fixture


class AuthenticatedActionReviewAuthorityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        phase194_fixture.AuthenticatedExpertReviewPhase194Tests.setUpClass()

    def setUp(self) -> None:
        fixture = phase194_fixture.AuthenticatedExpertReviewPhase194Tests(
            methodName="runTest"
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        self.adapter = AuthenticatedExpertReviewClosureVerifierAdapter(
            fixture.review,
            fixture.registry,
            workspace_store=fixture.workspace,
            runtime_catalog=fixture.catalog,
        )

    def test_phase194_current_closure_issues_exact_phase195_seal(self) -> None:
        _registration, _receipt, proof = self.fixture._close()
        current = _verify_current_expert_review_closure(
            self.adapter,
            proof.records,
            self.fixture.registry,
        )
        self.assertEqual(current, proof.records)

    def test_substituted_records_and_registry_fail_closed(self) -> None:
        _registration, _receipt, proof = self.fixture._close()
        substituted = replace(proof.records, receipts=())
        with self.assertRaisesRegex(ActionResolutionError, "substituted"):
            self.adapter.verify_current(substituted, self.fixture.registry)
        with self.assertRaisesRegex(ActionResolutionError, "registry"):
            self.adapter.verify_current(
                proof.records,
                replace(self.fixture.registry),
            )

    def test_phase194_current_failure_does_not_issue_phase195_seal(self) -> None:
        _registration, _receipt, proof = self.fixture._close()
        self.fixture.now = self.fixture.now.replace(year=2027)
        with self.assertRaisesRegex(ActionResolutionError, "not current"):
            self.adapter.verify_current(proof.records, self.fixture.registry)

    def test_malformed_closure_identity_fails_closed(self) -> None:
        _registration, _receipt, proof = self.fixture._close()
        malformed = replace(
            proof.records,
            closure=replace(proof.records.closure, document_json="{}"),
        )
        with self.assertRaisesRegex(ActionResolutionError, "not current"):
            self.adapter.verify_current(malformed, self.fixture.registry)


if __name__ == "__main__":
    unittest.main()

import copy
import hashlib
import json
import unittest
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import sunderkey

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from sunderkey.assessment_transport_contracts import (
    AdapterIdentity,
    AssessmentBinding,
    BrowserAction,
    BrowserActionIntent,
    MimeLimit,
    SessionBinding,
    TransportBudget,
    canonical_json,
)
from sunderkey.authorized_browser_runtime import (
    AuthorizedBrowserPolicy,
    AuthorizedBrowserRuntimeError,
    BrowserActionStatus,
    BrowserBudgetCompletion,
    BrowserBudgetReservation,
    BrowserBudgetState,
    BrowserDriverFailure,
    BrowserDriverResult,
    BrowserSafetySnapshot,
    execute_authorized_browser_action,
    verify_browser_action_receipt,
)
from sunderkey.execution_control_runtime import (
    AdmissionReceipt,
    AdmissionStatus,
    ClockObservation,
    ExecutionBinding,
    ExecutionRequest,
    HealthState,
)
from sunderkey.signed_scope_compiler import compile_signed_scope, verify_signed_scope

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "registry" / "schemas" / "authorized-browser-action-receipt-v1.schema.json"
FILES = (
    ROOT / "src" / "sunderkey" / "authorized_browser_runtime.py",
    Path(__file__),
    SCHEMA,
    ROOT / "docs" / "authorized-browser-runtime.md",
)
NOW = datetime(2026, 9, 20, 12, 0, tzinfo=UTC)
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
TECHNIQUE = "TECH-BROWSER-001"


def scope_spec() -> dict:
    return {
        "schema_version": 1,
        "issuer": "assessment-authority.example",
        "key_id": "scope-signing-key.2026-09",
        "nonce": "ABCDEFGHIJKLMNOP",
        "sequence_number": 1,
        "issued_at": "2026-09-19T00:00:00Z",
        "expires_at": "2026-09-26T00:00:00Z",
        "assessment_window": {
            "starts_at": "2026-09-19T00:00:00Z",
            "ends_at": "2026-09-25T00:00:00Z",
        },
        "targets": {
            "https_origins": ["https://app.example.test"],
            "exact_hosts": ["app.example.test"],
            "wildcard_subdomains": [],
            "cidrs": [],
            "ports": [443],
            "http_methods": ["GET", "POST"],
            "path_prefixes": ["/assess"],
        },
        "exclusions": [],
        "protected_endpoints": [],
        "budgets": {
            "max_requests": 20,
            "max_concurrency": 2,
            "max_requests_per_minute": 20,
        },
        "impact_tier_ceiling": "R2",
        "allowed_technique_ids": [TECHNIQUE],
        "data_handling": {
            "classification": "confidential",
            "collection": "minimized_content",
            "storage": "ephemeral_encrypted",
            "retention_days": 1,
            "redaction_required": True,
        },
        "emergency_stop_contact_id": "soc.primary",
    }


def verified_scope():
    key = Ed25519PrivateKey.generate()
    signed = compile_signed_scope(scope_spec(), key, now=NOW)
    return verify_signed_scope(
        signed,
        key.public_key(),
        expected_issuer="assessment-authority.example",
        expected_key_id="scope-signing-key.2026-09",
        now=NOW,
    )


class FakeClock:
    def __init__(self, ticks: tuple[int, ...] = tuple(range(101, 160))) -> None:
        self.ticks = list(ticks)

    def observe(self) -> ClockObservation:
        tick = self.ticks.pop(0)
        second = tick - 100
        return ClockObservation(f"2026-09-20T12:00:{second:02d}Z", tick)


class FakeSafety:
    def __init__(
        self,
        binding_sha256: str,
        request_sha256: str,
        *,
        health: HealthState = HealthState.HEALTHY,
        canceled: bool = False,
        emergency_stop: bool = False,
    ) -> None:
        self.snapshot = BrowserSafetySnapshot(
            binding_sha256,
            request_sha256,
            health,
            canceled,
            emergency_stop,
        )
        self.calls = 0

    def observe(self) -> BrowserSafetySnapshot:
        self.calls += 1
        return self.snapshot


class FakeDriver:
    def __init__(self, result: BrowserDriverResult, failure: Exception | None = None) -> None:
        self.result = result
        self.failure = failure
        self.calls = 0
        self.commands = []

    def perform(self, command):
        self.calls += 1
        self.commands.append(command)
        if self.failure is not None:
            raise self.failure
        return self.result


class FakeBudgetRepository:
    def __init__(self, state: BrowserBudgetState) -> None:
        self.state = state
        self.reservations: dict[str, BrowserBudgetReservation] = {}
        self.reserve_calls = 0
        self.complete_calls = 0

    def reserve(
        self,
        binding_sha256,
        session_id,
        action,
        idempotency_key,
        policy,
    ) -> BrowserBudgetReservation:
        self.reserve_calls += 1
        if idempotency_key in self.reservations:
            raise RuntimeError("duplicate budget reservation")
        before = self.state
        remaining_bytes = policy.max_total_bytes - before.bytes_observed
        remaining_time = policy.max_session_milliseconds - before.session_elapsed_milliseconds
        reserved_bytes = max(0, remaining_bytes)
        reserved_time = max(1, min(policy.max_action_milliseconds, remaining_time))
        reserved = BrowserBudgetState(
            actions_completed=before.actions_completed + 1,
            navigations_completed=before.navigations_completed
            + (1 if action is BrowserAction.NAVIGATE else 0),
            bytes_observed=before.bytes_observed + reserved_bytes,
            screenshots_captured=before.screenshots_captured
            + (1 if action is BrowserAction.SCREENSHOT_REFERENCE else 0),
            session_elapsed_milliseconds=before.session_elapsed_milliseconds + reserved_time,
        )
        reservation = BrowserBudgetReservation(
            binding_sha256=binding_sha256,
            session_id=session_id,
            action=action,
            idempotency_key=idempotency_key,
            state_before=before,
            state_reserved=reserved,
            reserved_observed_bytes=reserved_bytes,
            reserved_elapsed_milliseconds=reserved_time,
        )
        self.state = reserved
        self.reservations[idempotency_key] = reservation
        return reservation

    def complete(
        self,
        reservation,
        observed_bytes,
        screenshots_captured,
        elapsed_milliseconds,
    ) -> BrowserBudgetCompletion:
        self.complete_calls += 1
        before = reservation.state_before
        after = BrowserBudgetState(
            actions_completed=before.actions_completed + 1,
            navigations_completed=before.navigations_completed
            + (1 if reservation.action is BrowserAction.NAVIGATE else 0),
            bytes_observed=before.bytes_observed + observed_bytes,
            screenshots_captured=before.screenshots_captured + screenshots_captured,
            session_elapsed_milliseconds=before.session_elapsed_milliseconds + elapsed_milliseconds,
        )
        completion = BrowserBudgetCompletion(
            reservation_id=reservation.reservation_id,
            reservation_sha256=reservation.reservation_sha256,
            state_after=after,
            observed_bytes=observed_bytes,
            screenshots_captured=screenshots_captured,
            elapsed_milliseconds=elapsed_milliseconds,
        )
        self.state = after
        return completion


class AuthorizedBrowserRuntimePhase174Tests(unittest.TestCase):
    def test_public_exports_keep_identity(self) -> None:
        self.assertIs(sunderkey.AuthorizedBrowserPolicy, AuthorizedBrowserPolicy)
        self.assertIs(sunderkey.AuthorizedBrowserRuntimeError, AuthorizedBrowserRuntimeError)
        self.assertIs(
            sunderkey.execute_authorized_browser_action,
            execute_authorized_browser_action,
        )
        self.assertIs(
            sunderkey.verify_authorized_browser_action_receipt,
            verify_browser_action_receipt,
        )

    def setUp(self) -> None:
        self.scope = verified_scope()
        self.transport_budget = TransportBudget(
            max_steps=8,
            max_request_bytes=1024,
            max_response_bytes=4096,
            max_total_request_bytes=4096,
            max_total_response_bytes=8192,
            max_redirects=0,
            mime_limits=(MimeLimit("text/html", 4096),),
        )
        self.assessment_binding = AssessmentBinding(
            scope_id=self.scope.scope_id,
            scope_sha256=self.scope.content_sha256,
            task_id="context:browser-assessment-1",
            technique_id=TECHNIQUE,
            authority_refs=("authority:scope-owner",),
            evidence_hashes=(DIGEST_A,),
            impact_tier="R1",
            decision_at="2026-09-20T12:00:00Z",
            stop_conditions=("Stop on health change.",),
            adapter=AdapterIdentity("adapter.injected-browser", "1.0.0"),
            budget=self.transport_budget,
        )
        self.session = SessionBinding("session:browser-1", "principal:alice")
        self.intent = self.make_intent()
        self.execution_binding = ExecutionBinding(
            tenant_id="tenant:acme",
            context_id=self.assessment_binding.task_id,
            context_sha256=DIGEST_A,
            scope_id=self.scope.scope_id,
            scope_sha256=self.scope.content_sha256,
            target_id="target:app-example",
            target_sha256=DIGEST_B,
            session_id=self.session.session_id,
            lease_id="lease:browser-1",
            fence_epoch=7,
        )
        self.execution_request = self.make_execution_request()
        self.admission = self.make_admission(self.execution_request)
        self.policy = AuthorizedBrowserPolicy(
            binding=self.execution_binding,
            execution_policy_id=self.execution_request.policy_id,
            execution_policy_sha256=self.execution_request.policy_sha256,
            session_id=self.session.session_id,
            principal_label=self.session.principal_label,
            allowed_actions=tuple(BrowserAction),
            max_actions=20,
            max_navigations=5,
            max_total_bytes=8192,
            max_screenshots=4,
            max_action_milliseconds=5000,
            max_session_milliseconds=30000,
            max_selector_length=128,
        )
        self.budget = BrowserBudgetState(0, 0, 0, 0, 0)

    def make_intent(
        self,
        *,
        action: BrowserAction = BrowserAction.CLICK_SELECTOR,
        page_url: str = "https://app.example.test/assess/home",
        selector: str | None = "#run",
        value_reference: str | None = None,
        evidence_reference: str | None = None,
        session: SessionBinding | None = None,
    ) -> BrowserActionIntent:
        if action is BrowserAction.NAVIGATE:
            selector = None
        return BrowserActionIntent(
            binding=self.assessment_binding,
            sequence=1,
            action=action,
            page_url=page_url,
            session=session or self.session,
            selector_or_condition=selector,
            value_reference=value_reference,
            evidence_reference=evidence_reference,
        )

    def make_execution_request(
        self,
        intent: BrowserActionIntent | None = None,
        *,
        idempotency_key: str = "browser:assessment-1:step-1",
        attempt_number: int = 1,
        prior_execution_sha256: str | None = None,
    ) -> ExecutionRequest:
        selected = intent or self.intent
        return ExecutionRequest(
            binding=self.execution_binding,
            policy_id="ECP-0123456789ABCDEF0123456789ABCDEF",
            policy_sha256=DIGEST_A,
            idempotency_key=idempotency_key,
            operation_code="authorized_browser",
            payload_sha256=selected.intent_sha256,
            payload_size_bytes=len(canonical_json(selected.to_dict()).encode("ascii")),
            attempt_number=attempt_number,
            prior_execution_sha256=prior_execution_sha256,
            cleanup_obligation_sha256=DIGEST_B,
        )

    @staticmethod
    def make_admission(request: ExecutionRequest, admitted: bool = True) -> AdmissionReceipt:
        return AdmissionReceipt(
            request_id=request.request_id,
            request_sha256=request.request_sha256,
            policy_id=request.policy_id,
            policy_sha256=request.policy_sha256,
            status=AdmissionStatus.ADMITTED if admitted else AdmissionStatus.BLOCKED,
            reason=None if admitted else "canceled",
            observed_at="2026-09-20T12:00:00Z",
            monotonic_tick=100,
            state_before_sha256=DIGEST_A,
            state_after_sha256=DIGEST_B,
        )

    def default_result(self, **overrides) -> BrowserDriverResult:
        values = {
            "session_id": self.session.session_id,
            "principal_label": self.session.principal_label,
            "pre_url": "https://app.example.test/assess/home",
            "post_url": "https://app.example.test/assess/result",
            "attempts": 1,
            "elapsed_milliseconds": 25,
            "observed_bytes": 512,
            "screenshots_captured": 0,
            "evidence_reference": None,
            "action_complete": True,
        }
        values.update(overrides)
        return BrowserDriverResult(**values)

    def invoke(self, **overrides):
        execution_request = overrides.pop("execution_request", self.execution_request)
        safety = overrides.pop(
            "safety_monitor",
            FakeSafety(
                "sha256:"
                + hashlib.sha256(
                    canonical_json(execution_request.binding.to_dict()).encode("ascii")
                ).hexdigest(),
                execution_request.request_sha256,
            ),
        )
        values = {
            "scope": self.scope,
            "intent": self.intent,
            "execution_request": execution_request,
            "admission": self.admission,
            "policy": self.policy,
            "budget_repository": FakeBudgetRepository(self.budget),
            "clock": FakeClock(),
            "safety_monitor": safety,
            "driver": FakeDriver(self.default_result()),
        }
        values.update(overrides)
        return execute_authorized_browser_action(**values)

    def test_completed_action_is_one_call_and_content_addressed(self) -> None:
        driver = FakeDriver(self.default_result())
        receipt = self.invoke(driver=driver)
        self.assertEqual(receipt.status, BrowserActionStatus.COMPLETED)
        self.assertEqual(driver.calls, 1)
        self.assertEqual(driver.commands[0].maximum_attempts, 1)
        self.assertEqual(driver.commands[0].expected_origin, "https://app.example.test")
        verified = verify_browser_action_receipt(canonical_json(receipt.to_dict()))
        self.assertEqual(verified["receipt_id"], receipt.receipt_id)
        self.assertEqual(receipt.authority_effect, "none")
        self.assertEqual(receipt.qualification_effect, "none")
        self.assertEqual(receipt.pre_origin, receipt.post_origin)
        self.assertEqual(receipt.intended_origin, "https://app.example.test")
        self.assertIsNotNone(receipt.budget_reservation_sha256)
        self.assertIsNotNone(receipt.budget_completion_sha256)
        self.assertEqual(
            receipt.binding_sha256,
            "sha256:"
            + hashlib.sha256(
                canonical_json(self.execution_binding.to_dict()).encode("ascii")
            ).hexdigest(),
        )

    def test_scope_and_window_expiry_after_reservation_prevent_driver_call(self) -> None:
        for expires, ends in ((3, 3), (10, 3)):
            with self.subTest(expires=expires, ends=ends):
                spec = scope_spec()
                spec["expires_at"] = f"2026-09-20T12:00:{expires:02d}Z"
                spec["assessment_window"]["ends_at"] = f"2026-09-20T12:00:{ends:02d}Z"
                with mock.patch(f"{__name__}.scope_spec", return_value=spec):
                    self.setUp()
                driver = FakeDriver(self.default_result())
                repository = FakeBudgetRepository(self.budget)
                receipt = self.invoke(driver=driver, budget_repository=repository)
                self.assertEqual(receipt.status, BrowserActionStatus.REJECTED_BEFORE_DRIVER)
                self.assertEqual(receipt.reason, "scope_rejected")
                self.assertEqual(driver.calls, 0)
                self.assertFalse(receipt.driver_called)
                self.assertFalse(receipt.browser_action_performed)
                self.assertIsNotNone(receipt.budget_reservation_sha256)
                self.assertIsNotNone(receipt.budget_completion_sha256)
                self.assertEqual(receipt.observed_bytes, 0)
                self.assertEqual(receipt.screenshots_captured, 0)
                self.assertEqual(receipt.elapsed_milliseconds, 0)
                self.assertNotIn("driver_authorized", [item.stage for item in receipt.transcript])
                verify_browser_action_receipt(canonical_json(receipt.to_dict()))

    def test_valid_final_scope_recheck_preserves_existing_trace_observations(self) -> None:
        clock = FakeClock()
        receipt = self.invoke(clock=clock)
        self.assertEqual(
            [(item.stage, item.observed_at, item.monotonic_tick) for item in receipt.transcript],
            [
                (stage, f"2026-09-20T12:00:{index:02d}Z", 100 + index)
                for index, stage in enumerate(
                    (
                        "validated",
                        "budget_reserved",
                        "driver_authorized",
                        "postconditions_validated",
                    ),
                    start=1,
                )
            ],
        )
        self.assertEqual(clock.ticks[0], 105)
        verify_browser_action_receipt(canonical_json(receipt.to_dict()))

    def test_stop_changes_during_budget_reservation_prevent_driver_and_settle_zero_usage(
        self,
    ) -> None:
        for condition in ("canceled", "emergency_stop", "paused"):
            with self.subTest(condition=condition):
                safety = FakeSafety(
                    "sha256:"
                    + hashlib.sha256(
                        canonical_json(self.execution_binding.to_dict()).encode("ascii")
                    ).hexdigest(),
                    self.execution_request.request_sha256,
                )

                class ChangingRepository(FakeBudgetRepository):
                    def reserve(self, *args, **kwargs):
                        reservation = super().reserve(*args, **kwargs)
                        safety.snapshot = (
                            replace(safety.snapshot, health=HealthState.PAUSED)
                            if condition == "paused"
                            else replace(safety.snapshot, **{condition: True})
                        )
                        return reservation

                    def complete(self, reservation, observed_bytes, screenshots, elapsed):
                        self.complete_arguments = (
                            reservation,
                            observed_bytes,
                            screenshots,
                            elapsed,
                        )
                        self.completion = super().complete(
                            reservation, observed_bytes, screenshots, elapsed
                        )
                        return self.completion

                repository = ChangingRepository(self.budget)
                driver = FakeDriver(self.default_result())
                receipt = self.invoke(
                    budget_repository=repository, safety_monitor=safety, driver=driver
                )
                self.assertEqual(receipt.status, BrowserActionStatus.REJECTED_BEFORE_DRIVER)
                self.assertEqual(
                    receipt.reason, "health_not_healthy" if condition == "paused" else condition
                )
                self.assertEqual(driver.calls, 0)
                self.assertFalse(receipt.driver_called)
                self.assertFalse(receipt.browser_action_performed)
                self.assertEqual(safety.calls, 3)
                self.assertEqual(repository.reserve_calls, 1)
                self.assertEqual(repository.complete_calls, 1)
                reservation = repository.reservations[self.execution_request.idempotency_key]
                self.assertEqual(repository.complete_arguments, (reservation, 0, 0, 0))
                self.assertEqual(receipt.budget_reservation_id, reservation.reservation_id)
                self.assertEqual(receipt.budget_reservation_sha256, reservation.reservation_sha256)
                self.assertEqual(
                    receipt.budget_completion_sha256, repository.completion.completion_sha256
                )
                self.assertEqual(repository.completion.observed_bytes, 0)
                self.assertEqual(repository.completion.screenshots_captured, 0)
                self.assertEqual(repository.completion.elapsed_milliseconds, 0)
                self.assertEqual(
                    repository.state.actions_completed, self.budget.actions_completed + 1
                )
                self.assertEqual(receipt.observed_bytes, 0)
                self.assertEqual(receipt.screenshots_captured, 0)
                self.assertEqual(receipt.elapsed_milliseconds, 0)
                self.assertNotIn("driver_authorized", [item.stage for item in receipt.transcript])
                verify_browser_action_receipt(canonical_json(receipt.to_dict()))

    def test_late_stop_settlement_failure_keeps_reserved_evidence_without_driver(self) -> None:
        safety = FakeSafety(
            "sha256:"
            + hashlib.sha256(
                canonical_json(self.execution_binding.to_dict()).encode("ascii")
            ).hexdigest(),
            self.execution_request.request_sha256,
        )

        class FailingRepository(FakeBudgetRepository):
            def reserve(self, *args, **kwargs):
                reservation = super().reserve(*args, **kwargs)
                safety.snapshot = replace(safety.snapshot, canceled=True)
                return reservation

            def complete(self, reservation, observed_bytes, screenshots, elapsed):
                self.complete_calls += 1
                self.complete_arguments = (reservation, observed_bytes, screenshots, elapsed)
                raise RuntimeError("completion unavailable")

        repository = FailingRepository(self.budget)
        driver = FakeDriver(self.default_result())
        receipt = self.invoke(budget_repository=repository, safety_monitor=safety, driver=driver)
        reservation = repository.reservations[self.execution_request.idempotency_key]
        self.assertEqual(receipt.status, BrowserActionStatus.REJECTED_BEFORE_DRIVER)
        self.assertEqual(receipt.reason, "canceled")
        self.assertEqual(driver.calls, 0)
        self.assertFalse(receipt.driver_called)
        self.assertFalse(receipt.browser_action_performed)
        self.assertEqual(repository.reserve_calls, 1)
        self.assertEqual(repository.complete_calls, 1)
        self.assertEqual(repository.complete_arguments, (reservation, 0, 0, 0))
        self.assertEqual(repository.state, reservation.state_reserved)
        self.assertEqual(receipt.budget_reservation_id, reservation.reservation_id)
        self.assertEqual(receipt.budget_reservation_sha256, reservation.reservation_sha256)
        self.assertIsNone(receipt.budget_completion_sha256)
        verify_browser_action_receipt(canonical_json(receipt.to_dict()))

    def test_post_driver_stop_guard_remains_after_fresh_pre_driver_safety(self) -> None:
        for condition in ("canceled", "emergency_stop", "paused"):
            with self.subTest(condition=condition):

                class PostDriverSafety(FakeSafety):
                    def observe(self):
                        snapshot = super().observe()
                        if self.calls == 4:
                            return (
                                replace(snapshot, health=HealthState.PAUSED)
                                if condition == "paused"
                                else replace(snapshot, **{condition: True})
                            )
                        return snapshot

                safety = PostDriverSafety(
                    "sha256:"
                    + hashlib.sha256(
                        canonical_json(self.execution_binding.to_dict()).encode("ascii")
                    ).hexdigest(),
                    self.execution_request.request_sha256,
                )
                driver = FakeDriver(self.default_result())
                repository = FakeBudgetRepository(self.budget)
                receipt = self.invoke(
                    budget_repository=repository, safety_monitor=safety, driver=driver
                )
                self.assertEqual(receipt.status, BrowserActionStatus.POSTCONDITION_FAILED)
                self.assertEqual(
                    receipt.reason, "health_not_healthy" if condition == "paused" else condition
                )
                self.assertEqual(driver.calls, 1)
                self.assertTrue(receipt.driver_called)
                self.assertTrue(receipt.browser_action_performed)
                self.assertEqual(safety.calls, 4)
                self.assertEqual(repository.reserve_calls, 1)
                self.assertEqual(repository.complete_calls, 1)
                verify_browser_action_receipt(canonical_json(receipt.to_dict()))

    def test_driver_command_contains_references_and_no_resolved_secret(self) -> None:
        intent = self.make_intent(
            action=BrowserAction.FILL_REFERENCE,
            selector="#username",
            value_reference="credref:test/alice",
        )
        request = self.make_execution_request(intent)
        driver = FakeDriver(self.default_result())
        receipt = self.invoke(
            intent=intent,
            execution_request=request,
            admission=self.make_admission(request),
            driver=driver,
        )
        self.assertEqual(receipt.status, BrowserActionStatus.COMPLETED)
        command = driver.commands[0]
        self.assertEqual(command.value_reference, "credref:test/alice")
        self.assertNotIn("password", repr(command).lower())

    def test_every_closed_browser_action_reaches_one_injected_call(self) -> None:
        cases = (
            (BrowserAction.NAVIGATE, None, None, None),
            (BrowserAction.CLICK_SELECTOR, "#run", None, None),
            (
                BrowserAction.FILL_REFERENCE,
                "#username",
                "credref:test/alice",
                None,
            ),
            (BrowserAction.SUBMIT, "form#login", None, None),
            (BrowserAction.WAIT_CONDITION, "present:#ready", None, None),
            (BrowserAction.READ_METADATA, "title", None, None),
            (
                BrowserAction.SCREENSHOT_REFERENCE,
                "#result",
                None,
                "evidref:screenshot/result",
            ),
        )
        for action, selector, value_reference, evidence_reference in cases:
            with self.subTest(action=action):
                intent = self.make_intent(
                    action=action,
                    selector=selector,
                    value_reference=value_reference,
                    evidence_reference=evidence_reference,
                )
                request = self.make_execution_request(intent)
                result = self.default_result(
                    screenshots_captured=(1 if action is BrowserAction.SCREENSHOT_REFERENCE else 0),
                    evidence_reference=evidence_reference,
                )
                driver = FakeDriver(result)
                receipt = self.invoke(
                    intent=intent,
                    execution_request=request,
                    admission=self.make_admission(request),
                    driver=driver,
                )
                self.assertEqual(receipt.status, BrowserActionStatus.COMPLETED)
                self.assertEqual(driver.calls, 1)
                self.assertEqual(driver.commands[0].action, action)

    def test_blocked_or_mismatched_admission_never_calls_driver(self) -> None:
        for admission in (
            self.make_admission(self.execution_request, admitted=False),
            self.make_admission(
                replace(
                    self.execution_request,
                    idempotency_key="browser:assessment-1:other",
                    request_id="",
                    request_sha256="",
                )
            ),
        ):
            with self.subTest(admission=admission.status):
                driver = FakeDriver(self.default_result())
                receipt = self.invoke(admission=admission, driver=driver)
                self.assertEqual(receipt.status, BrowserActionStatus.REJECTED_BEFORE_DRIVER)
                self.assertEqual(driver.calls, 0)

    def test_out_of_scope_and_principal_mismatch_fail_before_driver(self) -> None:
        out = self.make_intent(page_url="https://outside.example/assess/home")
        out_request = self.make_execution_request(out)
        other_session = SessionBinding(self.session.session_id, "principal:bob")
        isolated = self.make_intent(session=other_session)
        isolated_request = self.make_execution_request(isolated)
        for intent, request in ((out, out_request), (isolated, isolated_request)):
            driver = FakeDriver(self.default_result())
            receipt = self.invoke(
                intent=intent,
                execution_request=request,
                admission=self.make_admission(request),
                driver=driver,
            )
            self.assertEqual(receipt.status, BrowserActionStatus.REJECTED_BEFORE_DRIVER)
            self.assertEqual(driver.calls, 0)

    def test_action_allowlist_and_selector_syntax_fail_closed(self) -> None:
        limited = replace(
            self.policy,
            allowed_actions=(BrowserAction.NAVIGATE,),
            policy_id="",
            policy_sha256="",
        )
        driver = FakeDriver(self.default_result())
        self.assertEqual(
            self.invoke(policy=limited, driver=driver).status,
            BrowserActionStatus.REJECTED_BEFORE_DRIVER,
        )
        self.assertEqual(driver.calls, 0)
        for selector in ("javascript:alert(1)", "input[type=file]"):
            with self.subTest(selector=selector), self.assertRaises(ValueError):
                self.make_intent(selector=selector)
        for selector in ("a[download]", "window.open"):
            intent = self.make_intent(selector=selector)
            request = self.make_execution_request(intent)
            driver = FakeDriver(self.default_result())
            receipt = self.invoke(
                intent=intent,
                execution_request=request,
                admission=self.make_admission(request),
                driver=driver,
            )
            self.assertEqual(receipt.status, BrowserActionStatus.REJECTED_BEFORE_DRIVER)
            self.assertEqual(driver.calls, 0)
        wait = self.make_intent(action=BrowserAction.WAIT_CONDITION, selector="ready now")
        request = self.make_execution_request(wait)
        driver = FakeDriver(self.default_result())
        receipt = self.invoke(
            intent=wait,
            execution_request=request,
            admission=self.make_admission(request),
            driver=driver,
        )
        self.assertEqual(receipt.status, BrowserActionStatus.REJECTED_BEFORE_DRIVER)
        self.assertEqual(driver.calls, 0)

    def test_action_navigation_byte_screenshot_and_time_ceilings_prevent_calls(self) -> None:
        cases = (
            replace(self.budget, actions_completed=self.policy.max_actions),
            replace(self.budget, bytes_observed=self.policy.max_total_bytes),
            replace(
                self.budget,
                session_elapsed_milliseconds=self.policy.max_session_milliseconds,
            ),
        )
        for budget in cases:
            driver = FakeDriver(self.default_result())
            receipt = self.invoke(
                budget_repository=FakeBudgetRepository(budget),
                driver=driver,
            )
            self.assertEqual(receipt.status, BrowserActionStatus.REJECTED_BEFORE_DRIVER)
            self.assertEqual(driver.calls, 0)

        navigate = self.make_intent(action=BrowserAction.NAVIGATE)
        request = self.make_execution_request(navigate)
        driver = FakeDriver(self.default_result())
        receipt = self.invoke(
            intent=navigate,
            execution_request=request,
            admission=self.make_admission(request),
            budget_repository=FakeBudgetRepository(
                replace(self.budget, navigations_completed=self.policy.max_navigations)
            ),
            driver=driver,
        )
        self.assertEqual(receipt.status, BrowserActionStatus.REJECTED_BEFORE_DRIVER)

    def test_atomic_repository_prevents_reset_counters_from_bypassing_action_ceiling(self) -> None:
        limited = replace(
            self.policy,
            max_actions=1,
            max_navigations=1,
            max_screenshots=1,
            policy_id="",
            policy_sha256="",
        )
        repository = FakeBudgetRepository(self.budget)
        first_driver = FakeDriver(self.default_result())
        first = self.invoke(
            policy=limited,
            budget_repository=repository,
            driver=first_driver,
        )
        self.assertEqual(first.status, BrowserActionStatus.COMPLETED)
        second_request = self.make_execution_request(idempotency_key="browser:assessment-1:step-2")
        second_driver = FakeDriver(self.default_result())
        second = self.invoke(
            execution_request=second_request,
            admission=self.make_admission(second_request),
            policy=limited,
            budget_repository=repository,
            driver=second_driver,
        )
        self.assertEqual(second.status, BrowserActionStatus.REJECTED_BEFORE_DRIVER)
        self.assertEqual(second.reason, "budget_rejected")
        self.assertEqual(first_driver.calls, 1)
        self.assertEqual(second_driver.calls, 0)
        self.assertEqual(repository.reserve_calls, 2)

    def test_tampered_budget_reservation_stops_before_driver(self) -> None:
        class TamperedReservationRepository(FakeBudgetRepository):
            def reserve(self, *args, **kwargs):
                value = super().reserve(*args, **kwargs)
                return replace(
                    value,
                    session_id="session:other",
                    reservation_id="",
                    reservation_sha256="",
                )

        driver = FakeDriver(self.default_result())
        receipt = self.invoke(
            budget_repository=TamperedReservationRepository(self.budget),
            driver=driver,
        )
        self.assertEqual(receipt.status, BrowserActionStatus.REJECTED_BEFORE_DRIVER)
        self.assertEqual(receipt.reason, "budget_rejected")
        self.assertEqual(driver.calls, 0)

    def test_tampered_budget_completion_is_terminal_after_one_driver_call(self) -> None:
        class TamperedCompletionRepository(FakeBudgetRepository):
            def complete(self, *args, **kwargs):
                value = super().complete(*args, **kwargs)
                return replace(
                    value,
                    observed_bytes=value.observed_bytes + 1,
                    completion_sha256="",
                )

        driver = FakeDriver(self.default_result())
        receipt = self.invoke(
            budget_repository=TamperedCompletionRepository(self.budget),
            driver=driver,
        )
        self.assertEqual(receipt.status, BrowserActionStatus.POSTCONDITION_FAILED)
        self.assertEqual(receipt.reason, "budget_rejected")
        self.assertEqual(driver.calls, 1)
        self.assertIsNone(receipt.budget_completion_sha256)

    def test_retry_attempt_is_rejected_and_driver_retry_evidence_fails(self) -> None:
        retry = self.make_execution_request(attempt_number=2, prior_execution_sha256=DIGEST_A)
        policy = replace(
            self.policy,
            execution_policy_id=retry.policy_id,
            execution_policy_sha256=retry.policy_sha256,
            policy_id="",
            policy_sha256="",
        )
        driver = FakeDriver(self.default_result())
        receipt = self.invoke(
            execution_request=retry,
            admission=self.make_admission(retry),
            policy=policy,
            driver=driver,
        )
        self.assertEqual(receipt.status, BrowserActionStatus.REJECTED_BEFORE_DRIVER)
        self.assertEqual(driver.calls, 0)

        receipt = self.invoke(driver=FakeDriver(self.default_result(attempts=2)))
        self.assertEqual(receipt.status, BrowserActionStatus.POSTCONDITION_FAILED)

    def test_cancel_health_emergency_stop_and_clock_rollback_fail_closed(self) -> None:
        binding_sha = (
            "sha256:"
            + hashlib.sha256(
                canonical_json(self.execution_binding.to_dict()).encode("ascii")
            ).hexdigest()
        )
        for safety in (
            FakeSafety(binding_sha, self.execution_request.request_sha256, canceled=True),
            FakeSafety(binding_sha, self.execution_request.request_sha256, emergency_stop=True),
            FakeSafety(
                binding_sha,
                self.execution_request.request_sha256,
                health=HealthState.UNHEALTHY,
            ),
        ):
            driver = FakeDriver(self.default_result())
            receipt = self.invoke(safety_monitor=safety, driver=driver)
            self.assertEqual(receipt.status, BrowserActionStatus.REJECTED_BEFORE_DRIVER)
            self.assertEqual(driver.calls, 0)
        driver = FakeDriver(self.default_result())
        receipt = self.invoke(clock=FakeClock((102, 101, 103, 104)), driver=driver)
        self.assertEqual(receipt.status, BrowserActionStatus.REJECTED_BEFORE_DRIVER)
        self.assertEqual(receipt.reason, "clock_rejected")
        self.assertEqual(driver.calls, 0)

    def test_driver_failures_are_terminal_and_never_retried(self) -> None:
        for failure, reason in (
            (BrowserDriverFailure("browser_unavailable"), "browser_unavailable"),
            (RuntimeError("unsafe details"), "driver_exception"),
        ):
            driver = FakeDriver(self.default_result(), failure)
            receipt = self.invoke(driver=driver)
            self.assertEqual(receipt.status, BrowserActionStatus.DRIVER_FAILED)
            self.assertEqual(receipt.reason, reason)
            self.assertEqual(driver.calls, 1)

    def test_postconditions_enforce_origin_session_and_forbidden_capabilities(self) -> None:
        results = (
            self.default_result(post_url="https://evil.example/assess/result"),
            self.default_result(principal_label="principal:bob"),
            self.default_result(popup_opened=True),
            self.default_result(upload_started=True),
            self.default_result(download_started=True),
            self.default_result(script_evaluated=True),
            self.default_result(arbitrary_file_accessed=True),
            self.default_result(clipboard_accessed=True),
            self.default_result(extension_used=True),
            self.default_result(elapsed_milliseconds=self.policy.max_action_milliseconds + 1),
            self.default_result(observed_bytes=self.policy.max_total_bytes + 1),
        )
        for result in results:
            with self.subTest(result=result):
                receipt = self.invoke(driver=FakeDriver(result))
                self.assertEqual(receipt.status, BrowserActionStatus.POSTCONDITION_FAILED)

    def test_screenshot_requires_one_matching_opaque_reference(self) -> None:
        intent = self.make_intent(
            action=BrowserAction.SCREENSHOT_REFERENCE,
            selector="#result",
            evidence_reference="evidref:screenshot/result",
        )
        request = self.make_execution_request(intent)
        good = self.default_result(
            screenshots_captured=1,
            evidence_reference="evidref:screenshot/result",
        )
        receipt = self.invoke(
            intent=intent,
            execution_request=request,
            admission=self.make_admission(request),
            driver=FakeDriver(good),
        )
        self.assertEqual(receipt.status, BrowserActionStatus.COMPLETED)
        bad = replace(good, evidence_reference="evidref:screenshot/other")
        receipt = self.invoke(
            intent=intent,
            execution_request=request,
            admission=self.make_admission(request),
            driver=FakeDriver(bad),
        )
        self.assertEqual(receipt.status, BrowserActionStatus.POSTCONDITION_FAILED)

    def test_strict_parser_rejects_unknown_duplicate_noncanonical_and_tampered(self) -> None:
        receipt = self.invoke().to_dict()
        encoded = canonical_json(receipt)
        verify_browser_action_receipt(encoded)
        with self.assertRaisesRegex(AuthorizedBrowserRuntimeError, "canonical"):
            verify_browser_action_receipt(json.dumps(receipt))
        duplicate = encoded[:-1] + ',"status":"completed"}'
        with self.assertRaisesRegex(AuthorizedBrowserRuntimeError, "duplicate"):
            verify_browser_action_receipt(duplicate)
        unknown = copy.deepcopy(receipt)
        unknown["extra"] = 1
        with self.assertRaisesRegex(AuthorizedBrowserRuntimeError, "fields"):
            verify_browser_action_receipt(canonical_json(unknown))
        tampered = copy.deepcopy(receipt)
        tampered["observed_bytes"] += 1
        with self.assertRaisesRegex(AuthorizedBrowserRuntimeError, "content address"):
            verify_browser_action_receipt(canonical_json(tampered))
        with self.assertRaisesRegex(AuthorizedBrowserRuntimeError, "ASCII"):
            verify_browser_action_receipt(encoded.encode("ascii") + b"\xff")

    def test_constructor_and_verifier_reject_cross_origin_state_against_intent(self) -> None:
        receipt = self.invoke()
        with self.assertRaisesRegex(AuthorizedBrowserRuntimeError, "intended origin"):
            replace(
                receipt,
                intended_origin="https://evil.example",
                receipt_id="",
                receipt_sha256="",
            )
        document = receipt.to_dict()
        document["intended_origin"] = "https://evil.example"
        body = {
            key: value
            for key, value in document.items()
            if key not in {"kind", "receipt_id", "receipt_sha256", "schema_version"}
        }
        digest = (
            "sha256:"
            + hashlib.sha256(
                canonical_json({"body": body, "kind": document["kind"]}).encode("ascii")
            ).hexdigest()
        )
        document["receipt_sha256"] = digest
        document["receipt_id"] = "ABR-" + digest[7:39].upper()
        with self.assertRaisesRegex(AuthorizedBrowserRuntimeError, "semantic"):
            verify_browser_action_receipt(document)

    def test_completed_receipt_requires_reservation_and_completion_evidence(self) -> None:
        receipt = self.invoke()
        with self.assertRaisesRegex(AuthorizedBrowserRuntimeError, "budget reservation"):
            replace(
                receipt,
                budget_reservation_id=None,
                budget_reservation_sha256=None,
                budget_completion_sha256=None,
                receipt_id="",
                receipt_sha256="",
            )

    def test_completed_receipt_requires_exact_completed_reason(self) -> None:
        receipt = self.invoke()
        with self.assertRaisesRegex(AuthorizedBrowserRuntimeError, "reason"):
            replace(
                receipt,
                reason="validation_rejected",
                receipt_id="",
                receipt_sha256="",
            )
        document = receipt.to_dict()
        document["reason"] = "validation_rejected"
        body = {
            key: value
            for key, value in document.items()
            if key not in {"kind", "receipt_id", "receipt_sha256", "schema_version"}
        }
        digest = (
            "sha256:"
            + hashlib.sha256(
                canonical_json({"body": body, "kind": document["kind"]}).encode("ascii")
            ).hexdigest()
        )
        document["receipt_sha256"] = digest
        document["receipt_id"] = "ABR-" + digest[7:39].upper()
        with self.assertRaisesRegex(AuthorizedBrowserRuntimeError, "semantic"):
            verify_browser_action_receipt(document)

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is unavailable")
    def test_receipts_validate_against_draft_2020_12_schema(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        completed = self.invoke().to_dict()
        validator.validate(completed)
        wrong_reason = copy.deepcopy(completed)
        wrong_reason["reason"] = "validation_rejected"
        self.assertTrue(list(validator.iter_errors(wrong_reason)))
        rejected = self.invoke(admission=self.make_admission(self.execution_request, False))
        validator.validate(rejected.to_dict())
        reserved_rejection = self.invoke(clock=FakeClock((102, 101, 103, 104)))
        self.assertEqual(reserved_rejection.status, BrowserActionStatus.REJECTED_BEFORE_DRIVER)
        self.assertIsNotNone(reserved_rejection.budget_reservation_sha256)
        validator.validate(reserved_rejection.to_dict())
        for field in (
            "budget_reservation_id",
            "budget_reservation_sha256",
            "budget_completion_sha256",
        ):
            altered = copy.deepcopy(completed)
            altered[field] = None
            self.assertTrue(list(validator.iter_errors(altered)))

    def test_artifacts_are_ascii_and_contain_no_marker_or_unicode_dash(self) -> None:
        markers = (
            "generated" + " by",
            "written" + " by ai",
            "as" + " an ai",
            "chat" + "gpt",
            "co" + "dex",
            "clau" + "de",
            "gem" + "ini",
            "co-authored" + "-by",
        )
        for path in FILES:
            raw = path.read_bytes()
            text = raw.decode("ascii")
            self.assertNotIn("\u2013", text)
            self.assertNotIn("\u2014", text)
            folded = text.casefold()
            for marker in markers:
                self.assertNotIn(marker, folded)


if __name__ == "__main__":
    unittest.main()

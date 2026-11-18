"""Explicit actor-binding time gates for offline provisioning and dispatch."""

from __future__ import annotations

import json
import unittest
from dataclasses import replace

from sunderkey.enterprise_identity_contracts import (
    AuthorizationRequest,
    Decision,
    Permission,
    authorize,
    canonical_json,
    canonical_sha256,
    validate_provisioning_command,
)
from sunderkey.enterprise_identity_runtime import EnterpriseIdentityRuntimeError
from tests.agents import test_enterprise_identity_runtime_phase176 as phase176

OUTSIDE_WINDOWS = (
    ("expired", "2026-09-20T00:00:00Z", "2026-09-20T11:59:59Z"),
    ("expiry_equal", "2026-09-20T00:00:00Z", phase176.NOW),
    ("future_start", "2026-09-20T12:00:01Z", "2026-09-21T00:00:00Z"),
)
GOLDEN_DOCUMENT_SHA256 = {
    "policy": "sha256:53362896fc3d0a1a4a383a97d8051da651ba9bbdfc5536b57ad37df39db3f2c0",
    "binding": "sha256:e14c079bc798051279e37b09d4ec18d0ce44cb8a96847b4c08352ac61c43fb8d",
    "command": "sha256:68105ca19908a22d9ef18d2a078115d82daebbff73dbd0f089a22514b68bb51c",
    "decision": "sha256:d179722946afdd2104b61e9086600010cdf9971790cbc1ecec46f0f8b1ff9e74",
    "admission": "sha256:3600a2ff418440112074834641bc3eef0cf1445a1625d234ea8f4cb4b7e4aa1c",
    "result": "sha256:ea39d580d94521ab870054fc2e6f6ebe01623469d00c17cd0e36124d8e2289f5",
    "receipt": "sha256:824f1a2fb15d415dda0461edd14185a85ede298aada4fd8f8a2dfdb553b7abd3",
}


class EnterpriseProvisioningCurrentnessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = phase176.EnterpriseIdentityRuntimePhase176Tests(methodName="runTest")
        self.fixture.setUp()

    def binding(self, valid_from: str, valid_until: str):
        return replace(
            self.fixture.binding,
            valid_from=valid_from,
            valid_until=valid_until,
        )

    def decision(self, binding, *, evaluated_at: str = phase176.NOW):
        return validate_provisioning_command(
            self.fixture.policy,
            self.fixture.command,
            actor_binding=binding,
            current_version=4,
            current_sha256=phase176.DIGEST_A,
            seen_idempotency={},
            evaluated_at=evaluated_at,
        )

    def authorization(self, binding, *, evaluated_at: str = phase176.NOW):
        return authorize(
            self.fixture.policy,
            (binding,),
            AuthorizationRequest(
                tenant_id=phase176.TENANT,
                subject_id=self.fixture.command.actor_subject_id,
                permission=Permission.IDENTITY_ADMIN,
                resource_tenant_id=phase176.TENANT,
                resource_id=self.fixture.command.resource_id,
                requested_at=evaluated_at,
                session_id="session:provisioning-currentness",
            ),
        )

    def test_outside_actor_windows_produce_explicit_deny(self) -> None:
        for case, valid_from, valid_until in OUTSIDE_WINDOWS:
            with self.subTest(case=case):
                decision = self.decision(self.binding(valid_from, valid_until))
                self.assertEqual(decision.decision, Decision.DENY)
                self.assertEqual(decision.reason_codes, ("actor_binding_outside_validity",))
                self.assertEqual(decision.evaluated_at, phase176.NOW)

    def test_outside_actor_windows_deny_before_every_injected_callback(self) -> None:
        for case, valid_from, valid_until in OUTSIDE_WINDOWS:
            dispatcher = phase176.TestDispatcher(lambda _command: self.fixture.result())
            store = phase176.AtomicStore()
            verifier = phase176.AdmissionVerifier()
            error = None
            try:
                self.fixture.dispatch(
                    dispatcher,
                    actor_binding=self.binding(valid_from, valid_until),
                    idempotency_store=store,
                    admission_verifier=verifier,
                )
            except EnterpriseIdentityRuntimeError as exc:
                error = exc
            with self.subTest(case=case, control="denial"):
                self.assertIsInstance(error, EnterpriseIdentityRuntimeError)
                self.assertEqual(str(error), "provisioning command was denied")
            for name, calls in (
                ("verifier", len(verifier.calls)),
                ("reservation", store.reserve_calls),
                ("dispatch", len(dispatcher.calls)),
                ("completion", store.complete_calls),
            ):
                with self.subTest(case=case, control=name):
                    self.assertEqual(calls, 0)
            with self.subTest(case=case, control="store"):
                self.assertEqual(store.records, {})

    def test_valid_from_equality_and_active_windows_keep_valid_dispatch(self) -> None:
        for case, binding in (
            ("active", self.fixture.binding),
            ("valid_from_equal", replace(self.fixture.binding, valid_from=phase176.NOW)),
        ):
            with self.subTest(case=case):
                decision = self.decision(binding)
                self.assertEqual(decision.decision, Decision.ALLOW)
                self.assertEqual(decision.to_dict(), self.fixture.decision().to_dict())
                dispatcher = phase176.TestDispatcher(lambda _command: self.fixture.result())
                store = phase176.AtomicStore()
                verifier = phase176.AdmissionVerifier()
                outcome = self.fixture.dispatch(
                    dispatcher,
                    actor_binding=binding,
                    idempotency_store=store,
                    admission_verifier=verifier,
                )
                self.assertEqual(outcome.receipt.status, "dispatched_non_production")
                self.assertEqual(outcome.receipt.dispatch_count, 1)
                self.assertEqual(
                    (
                        len(verifier.calls),
                        store.reserve_calls,
                        len(dispatcher.calls),
                        store.complete_calls,
                    ),
                    (1, 1, 1, 1),
                )
                self.assertEqual(
                    canonical_sha256(outcome.receipt.to_dict()), GOLDEN_DOCUMENT_SHA256["receipt"]
                )

    def test_ordinary_authorization_and_provisioning_agree_on_time_boundaries(self) -> None:
        cases = (
            *(
                (case, self.binding(start, end), Decision.DENY)
                for case, start, end in OUTSIDE_WINDOWS
            ),
            ("active", self.fixture.binding, Decision.ALLOW),
            (
                "valid_from_equal",
                replace(self.fixture.binding, valid_from=phase176.NOW),
                Decision.ALLOW,
            ),
        )
        for case, binding, expected in cases:
            with self.subTest(case=case):
                authorization = self.authorization(binding)
                provisioning = self.decision(binding)
                self.assertEqual(authorization.decision, expected)
                self.assertEqual(provisioning.decision, expected)
                if expected == Decision.DENY:
                    self.assertEqual(authorization.reason_codes, ("binding_outside_validity",))
                    self.assertEqual(provisioning.reason_codes, ("actor_binding_outside_validity",))

    def test_valid_native_golden_documents_and_identities_are_unchanged(self) -> None:
        admission = self.fixture.admission()
        result = self.fixture.result()
        outcome = self.fixture.dispatch(lambda _command: result, admission=admission)
        for name, value in (
            ("policy", self.fixture.policy),
            ("binding", self.fixture.binding),
            ("command", self.fixture.command),
            ("decision", self.fixture.decision()),
            ("admission", admission),
            ("result", result),
            ("receipt", outcome.receipt),
        ):
            with self.subTest(document=name):
                document = value.to_dict()
                self.assertEqual(json.loads(canonical_json(document)), document)
                self.assertEqual(canonical_sha256(document), GOLDEN_DOCUMENT_SHA256[name])
        self.assertEqual(self.fixture.decision().record_id, "EIC-BD59A4CE33E5D70B2E39CCD66D42A332")
        self.assertEqual(admission.admission_id, "EIA-814022BA514BAC38ED16ED5D90BA330A")
        self.assertEqual(outcome.receipt.receipt_id, "EIR-EE3B90F62B78606219D15616E3877780")
        self.assertEqual(outcome.receipt.to_dict()["effects"], phase176.NO_EFFECTS)

    def test_historical_binding_serialization_is_not_live_admission(self) -> None:
        binding = self.binding("2026-09-20T00:00:00Z", phase176.NOW)
        original_json = canonical_json(binding.to_dict())
        original_identity = (binding.record_id, binding.record_sha256)
        self.assertEqual(self.decision(binding).decision, Decision.DENY)
        document = json.loads(canonical_json(binding.to_dict()))
        self.assertEqual(document["valid_until"], phase176.NOW)
        self.assertEqual(canonical_json(document), original_json)
        self.assertEqual((binding.record_id, binding.record_sha256), original_identity)
        self.assertEqual(canonical_json(binding.to_dict()), original_json)

    def test_expired_actor_retry_denies_before_existing_replay_ports(self) -> None:
        expiry = "2026-09-20T12:00:01Z"
        binding = replace(self.fixture.binding, valid_until=expiry)
        dispatcher = phase176.TestDispatcher(lambda _command: self.fixture.result())
        store = phase176.AtomicStore()
        verifier = phase176.AdmissionVerifier()
        values = {
            "actor_binding": binding,
            "idempotency_store": store,
            "admission_verifier": verifier,
        }
        first = self.fixture.dispatch(dispatcher, **values)
        with self.assertRaisesRegex(EnterpriseIdentityRuntimeError, "reserved or completed"):
            self.fixture.dispatch(dispatcher, **values)
        previous_counts = (
            len(verifier.calls),
            store.reserve_calls,
            len(dispatcher.calls),
            store.complete_calls,
        )
        previous_records = dict(store.records)
        self.assertEqual(previous_counts, (2, 2, 1, 1))
        with self.assertRaisesRegex(
            EnterpriseIdentityRuntimeError, "provisioning command was denied"
        ):
            self.fixture.dispatch(dispatcher, evaluated_at=expiry, **values)
        self.assertEqual(
            (len(verifier.calls), store.reserve_calls, len(dispatcher.calls), store.complete_calls),
            previous_counts,
        )
        self.assertEqual(store.records, previous_records)
        self.assertEqual(first.receipt.status, "dispatched_non_production")
        self.assertEqual(self.decision(binding, evaluated_at=phase176.NOW).decision, Decision.ALLOW)
        self.assertEqual(self.decision(binding, evaluated_at=expiry).decision, Decision.DENY)


if __name__ == "__main__":
    unittest.main()

"""Synthetic scenario consent planning never executes or delivers a scenario."""

from __future__ import annotations

import unittest
from dataclasses import replace

from sunderkey.synthetic_scenario_planning import (
    ScenarioDisposition,
    SyntheticScenarioConsent,
    SyntheticScenarioError,
    SyntheticScenarioRequest,
    plan_synthetic_scenarios,
)

SCOPE = "sha256:" + "a" * 64
SOURCE = "sha256:" + "b" * 64
PRINCIPAL = "synthetic-principal:sha256:" + "c" * 64
OTHER_PRINCIPAL = "synthetic-principal:sha256:" + "d" * 64
SURFACE = "surface:sha256:" + "e" * 64
OTHER_SURFACE = "surface:sha256:" + "f" * 64
AT = "2026-09-23T13:00:00Z"


def request(
    request_id="request:one", *, principal=PRINCIPAL,
    surface=SURFACE, kind="synthetic_phishing_impact",
    scenario_id="scenario:one", tenant="tenant:one", scope=SCOPE,
    created_at="2026-09-23T12:00:00Z",
    window_start="2026-09-23T14:00:00Z",
    window_end="2026-09-23T15:00:00Z",
):
    return SyntheticScenarioRequest(
        request_id=request_id, tenant_id=tenant, scope_sha256=scope,
        scenario_id=scenario_id, kind=kind,
        synthetic_principal_ref=principal, surface_ref=surface,
        created_at=created_at, window_start=window_start,
        window_end=window_end, source_sha256=SOURCE,
    )


def consent(
    *, principals=(PRINCIPAL,), surfaces=(SURFACE,),
    kind="synthetic_phishing_impact", scenario_id="scenario:one",
    tenant="tenant:one", scope=SCOPE,
    issued_at="2026-09-23T11:00:00Z",
    expires_at="2026-09-24T11:00:00Z",
):
    return SyntheticScenarioConsent(
        tenant_id=tenant, scope_sha256=scope, scenario_id=scenario_id,
        kind=kind, synthetic_principal_refs=principals, surface_refs=surfaces,
        issued_at=issued_at, expires_at=expires_at, source_sha256=SOURCE,
    )


def plan(requests, consents=(), **changes):
    values = {
        "tenant_id": "tenant:one", "scope_sha256": SCOPE,
        "planned_at": AT, "requests": tuple(requests), "consents": tuple(consents),
    }
    values.update(changes)
    return plan_synthetic_scenarios(**values)


class SyntheticScenarioPlanningTests(unittest.TestCase):
    def test_exact_current_consent_proposes_only_human_review(self):
        output = plan((request(),), (consent(),))
        self.assertEqual(output.items[0].disposition, ScenarioDisposition.REVIEW_CANDIDATE)
        self.assertEqual(
            output.items[0].matching_consent_sha256, (consent().consent_sha256,),
        )
        effects = output.to_dict()["effects"]
        self.assertEqual(effects["delivery"], "none")
        self.assertEqual(effects["credential_collection"], "none")
        self.assertEqual(effects["target_interaction"], "none")
        self.assertIn("cleanup_receipt", output.items[0].to_dict()["evidence_obligations"])

    def test_mismatched_identity_surface_kind_or_scenario_blocks_candidate(self):
        for item in (
            consent(principals=(OTHER_PRINCIPAL,)),
            consent(surfaces=(OTHER_SURFACE,)),
            consent(kind="synthetic_insider_start_position"),
            consent(scenario_id="scenario:other"),
            consent(expires_at="2026-09-23T12:30:00Z"),
            consent(expires_at="2026-09-23T14:30:00Z"),
        ):
            with self.subTest(consent=item):
                output = plan((request(),), (item,))
                self.assertEqual(
                    output.items[0].disposition,
                    ScenarioDisposition.NO_MATCHING_CONSENT,
                )
                self.assertEqual(output.items[0].matching_consent_sha256, ())

    def test_expired_request_is_not_a_current_candidate(self):
        expired = request(
            created_at="2026-09-23T09:00:00Z",
            window_start="2026-09-23T10:00:00Z",
            window_end="2026-09-23T11:00:00Z",
        )
        output = plan((expired,), (consent(),))
        self.assertEqual(output.items[0].disposition, ScenarioDisposition.EXPIRED_REQUEST)
        self.assertEqual(output.items[0].matching_consent_sha256, ())

    def test_synthetic_insider_kind_uses_same_exact_boundary(self):
        insider = request(kind="synthetic_insider_start_position")
        approval = consent(kind="synthetic_insider_start_position")
        self.assertEqual(
            plan((insider,), (approval,)).items[0].disposition,
            ScenarioDisposition.REVIEW_CANDIDATE,
        )

    def test_duplicate_order_is_deterministic_and_conflicts_fail_closed(self):
        first = request("request:first")
        second = request("request:second", kind="synthetic_insider_start_position")
        left = plan((first, second, first), (consent(), consent()))
        right = plan((second, first), (consent(),))
        self.assertEqual(left.to_dict(), right.to_dict())
        with self.assertRaisesRegex(SyntheticScenarioError, "conflicting evidence"):
            plan((request(), request(surface=OTHER_SURFACE)))

    def test_invalid_population_or_secret_like_reference_fails_closed(self):
        with self.assertRaisesRegex(SyntheticScenarioError, "opaque synthetic reference"):
            request(principal="person@example.com")
        with self.assertRaisesRegex(SyntheticScenarioError, "opaque synthetic reference"):
            request(principal="principal:sha256:" + "c" * 64)
        with self.assertRaisesRegex(SyntheticScenarioError, "opaque synthetic reference"):
            consent(surfaces=("https://example.com",))
        with self.assertRaisesRegex(SyntheticScenarioError, "bounded and canonical"):
            consent(principals=(PRINCIPAL, PRINCIPAL))

    def test_time_limits_and_tenant_scope_are_enforced(self):
        with self.assertRaisesRegex(SyntheticScenarioError, "hard limit"):
            request(window_end="2026-09-25T15:00:00Z")
        with self.assertRaisesRegex(SyntheticScenarioError, "hard limit"):
            consent(expires_at="2026-10-20T11:00:00Z")
        with self.assertRaisesRegex(SyntheticScenarioError, "future-dated"):
            plan((request(created_at="2026-09-23T13:30:00Z"),))
        with self.assertRaisesRegex(SyntheticScenarioError, "future-dated"):
            plan((), (consent(issued_at="2026-09-23T13:30:00Z"),))
        with self.assertRaisesRegex(SyntheticScenarioError, "crosses tenant or scope"):
            plan((request(tenant="tenant:other"),))
        with self.assertRaisesRegex(SyntheticScenarioError, "crosses tenant or scope"):
            plan((request(),), (consent(scope="sha256:" + "9" * 64),))

    def test_hash_tampering_and_plan_coverage_fail_closed(self):
        with self.assertRaisesRegex(SyntheticScenarioError, "request_sha256"):
            replace(request(), surface_ref=OTHER_SURFACE)
        with self.assertRaisesRegex(SyntheticScenarioError, "consent_sha256"):
            replace(consent(), surface_refs=(OTHER_SURFACE,))
        output = plan((request(),), (consent(),))
        with self.assertRaisesRegex(SyntheticScenarioError, "plan_sha256"):
            replace(output, planned_at="2026-09-23T13:01:00Z")
        with self.assertRaisesRegex(SyntheticScenarioError, "review items"):
            replace(output, items=(), plan_sha256="")
        detached = output.to_dict()
        detached["effects"]["delivery"] = "tampered"
        self.assertEqual(output.to_dict()["effects"]["delivery"], "none")


if __name__ == "__main__":
    unittest.main()

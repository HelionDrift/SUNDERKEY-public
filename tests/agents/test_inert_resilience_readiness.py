"""Inert resilience metadata cannot become containment or recovery proof."""

from __future__ import annotations

import unittest
from dataclasses import replace

from sunderkey.inert_resilience_readiness import (
    InertReadinessError,
    InertReadinessObservation,
    InertReadinessScenario,
    ReadinessFacet,
    ReadinessStatus,
    review_inert_readiness,
)

SCOPE = "sha256:" + "a" * 64
SOURCE = "sha256:" + "b" * 64
ASSET = "synthetic-asset:sha256:" + "c" * 64
CANARY = "inert-canary:sha256:" + "d" * 64
AT = "2026-09-23T13:00:00Z"


def scenario(*, tenant="tenant:one", scope=SCOPE, asset=ASSET,
             expires_at="2026-09-24T12:00:00Z"):
    return InertReadinessScenario(
        scenario_id="scenario:one", tenant_id=tenant, scope_sha256=scope,
        synthetic_asset_ref=asset, inert_canary_ref=CANARY,
        source_sha256=SOURCE, recorded_at="2026-09-23T12:00:00Z",
        expires_at=expires_at,
    )


def observation(
    facet="propagation_boundary", *, outcome="protected_asserted",
    selected_scenario=None, tenant="tenant:one", scope=SCOPE,
    observed_at="2026-09-23T12:00:00Z",
    expires_at="2026-09-24T12:00:00Z",
):
    selected_scenario = selected_scenario or scenario()
    return InertReadinessObservation(
        tenant_id=tenant, scope_sha256=scope,
        scenario_sha256=selected_scenario.scenario_sha256,
        facet=facet, outcome=outcome, source_sha256=SOURCE,
        observed_at=observed_at, expires_at=expires_at,
    )


def complete():
    return tuple(observation(facet.value) for facet in ReadinessFacet)


def review(items=(), *, selected_scenario=None, reviewed_at=AT):
    return review_inert_readiness(
        scenario=selected_scenario or scenario(),
        observations=tuple(items), reviewed_at=reviewed_at,
    )


class InertResilienceReadinessTests(unittest.TestCase):
    def test_complete_assertions_remain_review_only_not_recovery_proof(self):
        output = review(complete())
        self.assertEqual(output.status, ReadinessStatus.EVIDENCE_FOR_REVIEW)
        rendered = output.to_dict()
        self.assertFalse(rendered["successful_containment_proven"])
        self.assertFalse(rendered["successful_restoration_proven"])
        self.assertTrue(rendered["independent_review_required"])
        for effect in ("encryption", "exfiltration", "data_mutation", "network"):
            self.assertEqual(rendered["effects"][effect], "none")

    def test_missing_and_not_observed_facets_are_inconclusive(self):
        self.assertEqual(review().status, ReadinessStatus.INCONCLUSIVE)
        self.assertEqual(review(complete()[:-1]).status, ReadinessStatus.INCONCLUSIVE)
        unknown = (
            observation("propagation_boundary", outcome="not_observed"),
            *complete()[1:],
        )
        self.assertEqual(review(unknown).status, ReadinessStatus.INCONCLUSIVE)

    def test_asserted_gap_requires_review_without_claiming_disruption(self):
        items = (
            observation("egress_policy", outcome="gap_asserted"),
            *(item for item in complete() if item.facet is not ReadinessFacet.EGRESS_POLICY),
        )
        output = review(items)
        self.assertEqual(output.status, ReadinessStatus.GAP_REQUIRES_REVIEW)
        self.assertIn("facet_gap_asserted", output.review_reasons)
        self.assertFalse(output.to_dict()["successful_containment_proven"])

    def test_stale_scenario_or_facet_cannot_prove_current_readiness(self):
        expired = scenario(expires_at="2026-09-23T12:30:00Z")
        items = tuple(observation(facet.value, selected_scenario=expired)
                      for facet in ReadinessFacet)
        self.assertEqual(
            review(items, selected_scenario=expired).status,
            ReadinessStatus.STALE_EVIDENCE,
        )
        stale = (
            observation("propagation_boundary", expires_at="2026-09-23T12:30:00Z"),
            *complete()[1:],
        )
        self.assertEqual(review(stale).status, ReadinessStatus.STALE_EVIDENCE)

    def test_order_duplicate_and_conflict_handling(self):
        items = complete()
        self.assertEqual(review(items).to_dict(), review(tuple(reversed(items))).to_dict())
        self.assertEqual(
            review((items[0], items[0], items[1])).to_dict(),
            review((items[1], items[0])).to_dict(),
        )
        with self.assertRaisesRegex(InertReadinessError, "conflicting evidence"):
            review((observation(), observation(outcome="gap_asserted")))

    def test_binding_future_and_retention_fail_closed(self):
        with self.assertRaisesRegex(InertReadinessError, "crosses scenario binding"):
            review((observation(tenant="tenant:other"),))
        with self.assertRaisesRegex(InertReadinessError, "crosses scenario binding"):
            review((observation(scope="sha256:" + "e" * 64),))
        with self.assertRaisesRegex(InertReadinessError, "future-dated"):
            review((observation(observed_at="2026-09-23T14:00:00Z",
                                expires_at="2026-09-24T14:00:00Z"),))
        with self.assertRaisesRegex(InertReadinessError, "hard limit"):
            scenario(expires_at="2026-10-01T12:00:00Z")
        with self.assertRaisesRegex(InertReadinessError, "hard limit"):
            observation(expires_at="2026-10-01T12:00:00Z")

    def test_nonopaque_or_tampered_records_fail_closed(self):
        with self.assertRaisesRegex(InertReadinessError, "opaque synthetic reference"):
            scenario(asset="production-database")
        with self.assertRaisesRegex(InertReadinessError, "scenario_sha256"):
            replace(scenario(), synthetic_asset_ref="synthetic-asset:sha256:" + "f" * 64)
        with self.assertRaisesRegex(InertReadinessError, "observation_sha256"):
            replace(observation(), outcome="gap_asserted")
        output = review(complete())
        with self.assertRaisesRegex(InertReadinessError, "review_sha256"):
            replace(output, reviewed_at="2026-09-23T13:01:00Z")
        with self.assertRaisesRegex(InertReadinessError, "conflicts with reasons"):
            replace(output, status="inconclusive", review_sha256="")
        detached = output.to_dict()
        detached["effects"]["encryption"] = "tampered"
        self.assertEqual(output.to_dict()["effects"]["encryption"], "none")


if __name__ == "__main__":
    unittest.main()

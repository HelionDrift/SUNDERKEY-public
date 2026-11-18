"""Phase 164 capacity and economics contract coverage."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

import sunderkey
from sunderkey.capacity_economics_contracts import (
    NO_EFFECTS,
    AdmissionDisposition,
    AdmissionRecommendation,
    CapacityEconomicsContract,
    CapacityEconomicsError,
    CapacityPolicy,
    CostAttribution,
    DemandForecast,
    EvidenceProvenance,
    ForecastMetric,
    MeasurementDimensions,
    MeasurementWindow,
    ProviderQuotaSnapshot,
    QuotaCounter,
    build_contract,
    canonical_json,
    parse_contract,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "registry" / "schemas" / "capacity-economics-contract-v1.schema.json"
SOURCE_FILES = (
    ROOT / "src" / "sunderkey" / "capacity_economics_contracts.py",
    ROOT / "tests" / "agents" / "test_capacity_economics_contracts_phase164.py",
    SCHEMA,
    ROOT / "docs" / "capacity-economics-contracts.md",
)
HASH_A = "sha256:" + "a" * 64
HASH_B = "sha256:" + "b" * 64


class CapacityEconomicsContractsTests(unittest.TestCase):
    def test_public_package_exports_are_available(self) -> None:
        self.assertIs(
            sunderkey.build_capacity_economics_contract,
            build_contract,
        )
        self.assertIs(
            sunderkey.parse_capacity_economics_contract,
            parse_contract,
        )

    def dimensions(self, **changes: str) -> MeasurementDimensions:
        values = {
            "tenant_ref": "tenantref:tenant-a",
            "assessment_ref": "assessmentref:assessment-a",
            "provider_ref": "providerref:openai",
            "region": "us-central",
            "worker_pool_ref": "workerpoolref:pool-a",
        }
        values.update(changes)
        return MeasurementDimensions(**values)

    def window(self, **changes: object) -> MeasurementWindow:
        values: dict[str, object] = {
            "dimensions": self.dimensions(),
            "window_start": "2026-09-20T00:00:00Z",
            "window_end": "2026-09-20T00:10:00Z",
            "observed_at": "2026-09-20T00:10:00Z",
            "provenance": EvidenceProvenance.MEASURED_TEST,
            "source_sha256s": (HASH_A,),
            "custody_refs": (),
            "worker_capacity_milliseconds": 1_000,
            "worker_busy_milliseconds": 500,
            "queue_time_samples_milliseconds": (10, 40),
            "requests": 2,
            "input_tokens": 100,
            "output_tokens": 50,
            "model_cost_micros": 100,
            "tool_cost_micros": 20,
            "storage_cost_micros": 5,
            "storage_start_bytes": 1_000,
            "storage_end_bytes": 1_250,
            "validated_findings": 1,
        }
        values.update(changes)
        return MeasurementWindow(**values)

    def attribution(self, window: MeasurementWindow, **changes: object) -> CostAttribution:
        values: dict[str, object] = {
            "tenant_ref": window.dimensions.tenant_ref,
            "assessment_ref": window.dimensions.assessment_ref,
            "source_window_ids": (window.window_id,),
            "requests": window.requests,
            "input_tokens": window.input_tokens,
            "output_tokens": window.output_tokens,
            "storage_growth_bytes": window.storage_growth_bytes,
            "validated_findings": window.validated_findings,
            "model_cost_micros": window.model_cost_micros,
            "tool_cost_micros": window.tool_cost_micros,
            "storage_cost_micros": window.storage_cost_micros,
        }
        values.update(changes)
        return CostAttribution(**values)

    def quota(self, **changes: object) -> ProviderQuotaSnapshot:
        quotas = tuple(
            QuotaCounter(name, unit, 10_000, 1_000, 500)
            for name, unit in {
                "concurrent_requests": "requests",
                "cost_per_day": "microusd",
                "input_tokens_per_minute": "tokens",
                "output_tokens_per_minute": "tokens",
                "requests_per_minute": "requests",
            }.items()
        )
        values: dict[str, object] = {
            "provider_ref": "providerref:openai",
            "region": "us-central",
            "observed_at": "2026-09-20T00:12:00Z",
            "expires_at": "2026-09-20T01:12:00Z",
            "provenance": EvidenceProvenance.MEASURED_TEST,
            "source_sha256s": (HASH_A,),
            "custody_refs": (),
            "quotas": quotas,
        }
        values.update(changes)
        return ProviderQuotaSnapshot(**values)

    def forecast(self, window: MeasurementWindow, **changes: object) -> DemandForecast:
        metrics = tuple(
            ForecastMetric(name, unit, 100, 200, 300)
            for name, unit in {
                "concurrent_requests": "requests",
                "cost_per_day": "microusd",
                "input_tokens_per_minute": "tokens",
                "output_tokens_per_minute": "tokens",
                "requests_per_minute": "requests",
            }.items()
        )
        values: dict[str, object] = {
            "provider_ref": window.dimensions.provider_ref,
            "region": window.dimensions.region,
            "created_at": "2026-09-20T00:12:00Z",
            "horizon_start": "2026-09-20T00:15:00Z",
            "horizon_end": "2026-09-20T01:15:00Z",
            "confidence_basis_points": 9_000,
            "source_window_ids": (window.window_id,),
            "source_sha256s": (HASH_B,),
            "metrics": metrics,
        }
        values.update(changes)
        return DemandForecast(**values)

    def policy(self, **changes: object) -> CapacityPolicy:
        values: dict[str, object] = {
            "policy_version": "capacity.1",
            "maximum_measurement_age_seconds": 3_600,
            "maximum_quota_age_seconds": 3_600,
            "maximum_forecast_age_seconds": 3_600,
            "maximum_forecast_horizon_seconds": 86_400,
            "minimum_forecast_confidence_basis_points": 8_000,
            "minimum_quota_headroom_basis_points": 2_000,
            "maximum_worker_utilization_basis_points": 9_000,
            "maximum_queue_p95_milliseconds": 1_000,
            "maximum_assessment_cost_micros": 1_000,
            "maximum_cost_per_validated_finding_micros": 500,
        }
        values.update(changes)
        return CapacityPolicy(**values)

    def contract(self, **changes: object) -> CapacityEconomicsContract:
        window = changes.pop("window", self.window())
        attribution = changes.pop("attribution", self.attribution(window))
        quota = changes.pop("quota", self.quota())
        forecast = changes.pop("forecast", self.forecast(window))
        values: dict[str, object] = {
            "as_of": "2026-09-20T00:20:00Z",
            "target_tenant_ref": window.dimensions.tenant_ref,
            "target_assessment_ref": window.dimensions.assessment_ref,
            "target_provider_ref": window.dimensions.provider_ref,
            "target_region": window.dimensions.region,
            "measurement_windows": (window,),
            "attributions": (attribution,),
            "quota_snapshots": (quota,),
            "forecasts": (forecast,),
            "policy": self.policy(),
        }
        values.update(changes)
        return build_contract(**values)

    def test_valid_contract_round_trip_schema_and_content_addresses(self) -> None:
        contract = self.contract()
        payload = contract.to_dict()
        parsed = parse_contract(canonical_json(payload))
        self.assertEqual(parsed, contract)
        self.assertEqual(payload["effects"], NO_EFFECTS)
        self.assertEqual(contract.recommendation.disposition, AdmissionDisposition.ADMIT)
        Draft202012Validator(json.loads(SCHEMA.read_text(encoding="utf-8"))).validate(payload)
        self.assertTrue(contract.contract_id.startswith("CEC-"))
        self.assertTrue(contract.contract_sha256.startswith("sha256:"))

    def test_window_derives_percentiles_utilization_growth_and_cost(self) -> None:
        window = self.window()
        self.assertEqual(window.duration_seconds, 600)
        self.assertEqual(window.worker_utilization_basis_points, 5_000)
        self.assertEqual(window.queue_p50_milliseconds, 10)
        self.assertEqual(window.queue_p95_milliseconds, 40)
        self.assertEqual(window.storage_growth_bytes, 250)
        self.assertEqual(window.total_cost_micros, 125)
        attribution = self.attribution(window)
        self.assertEqual(attribution.cost_per_validated_finding_micros, 125)

    def test_negative_values_mixed_units_and_incomplete_dimensions_fail_closed(self) -> None:
        with self.assertRaisesRegex(CapacityEconomicsError, "non-negative"):
            self.window(tool_cost_micros=-1)
        with self.assertRaisesRegex(CapacityEconomicsError, "unit"):
            QuotaCounter("requests_per_minute", "tokens", 100, 1, 1)
        with self.assertRaisesRegex(CapacityEconomicsError, "every required quota"):
            self.quota(quotas=(QuotaCounter("requests_per_minute", "requests", 100, 1, 1),))
        with self.assertRaisesRegex(CapacityEconomicsError, "queue samples"):
            self.window(queue_time_samples_milliseconds=(10,))

    def test_production_claims_require_custody_references(self) -> None:
        with self.assertRaisesRegex(CapacityEconomicsError, "custody"):
            self.window(provenance=EvidenceProvenance.MEASURED_PRODUCTION)
        with self.assertRaisesRegex(CapacityEconomicsError, "custody"):
            self.quota(provenance=EvidenceProvenance.MEASURED_PRODUCTION)
        window = self.window(
            provenance=EvidenceProvenance.MEASURED_PRODUCTION,
            custody_refs=("custodyref:metrics-ledger-1",),
        )
        self.assertEqual(window.provenance, EvidenceProvenance.MEASURED_PRODUCTION)

    def test_overlapping_windows_and_double_attribution_fail_closed(self) -> None:
        first = self.window()
        second = self.window(
            window_start="2026-09-20T00:05:00Z",
            window_end="2026-09-20T00:15:00Z",
            observed_at="2026-09-20T00:15:00Z",
        )
        with self.assertRaisesRegex(CapacityEconomicsError, "overlap"):
            CapacityEconomicsContract(
                (first, second),
                (self.attribution(first), self.attribution(second)),
                (self.quota(),),
                (self.forecast(first),),
                self.policy(),
                self.contract().recommendation,
            )
        with self.assertRaisesRegex(CapacityEconomicsError, "attributed more than once"):
            CapacityEconomicsContract(
                (first,),
                (self.attribution(first), self.attribution(first)),
                (self.quota(),),
                (self.forecast(first),),
                self.policy(),
                self.contract().recommendation,
            )

    def test_attribution_totals_must_be_derived(self) -> None:
        window = self.window()
        attribution = self.attribution(window, requests=3)
        with self.assertRaisesRegex(CapacityEconomicsError, "not derived"):
            self.contract(window=window, attribution=attribution)

    def test_quota_oversubscription_and_forecast_mismatch_fail_closed(self) -> None:
        with self.assertRaisesRegex(CapacityEconomicsError, "oversubscribed"):
            QuotaCounter("requests_per_minute", "requests", 100, 90, 20)
        window = self.window()
        mismatch = self.forecast(window, provider_ref="providerref:other")
        with self.assertRaisesRegex(CapacityEconomicsError, "target dimensions"):
            self.contract(window=window, forecast=mismatch)
        bad_source = self.window(
            dimensions=self.dimensions(
                provider_ref="providerref:other",
                tenant_ref="tenantref:tenant-b",
                assessment_ref="assessmentref:assessment-b",
            ),
            source_sha256s=(HASH_B,),
        )
        forecast = self.forecast(window, source_window_ids=(bad_source.window_id,))
        with self.assertRaisesRegex(CapacityEconomicsError, "source dimensions"):
            build_contract(
                as_of="2026-09-20T00:20:00Z",
                target_tenant_ref=window.dimensions.tenant_ref,
                target_assessment_ref=window.dimensions.assessment_ref,
                target_provider_ref=window.dimensions.provider_ref,
                target_region=window.dimensions.region,
                measurement_windows=(window, bad_source),
                attributions=(self.attribution(window), self.attribution(bad_source)),
                quota_snapshots=(self.quota(), self.quota(provider_ref="providerref:other")),
                forecasts=(forecast, self.forecast(bad_source)),
                policy=self.policy(),
            )

    def test_stale_evidence_and_capacity_thresholds_deny_admission(self) -> None:
        window = self.window(
            worker_busy_milliseconds=950,
            queue_time_samples_milliseconds=(10, 2_000),
        )
        contract = self.contract(
            window=window,
            attribution=self.attribution(window),
            forecast=self.forecast(window),
            as_of="2026-09-20T02:20:00Z",
        )
        self.assertEqual(contract.recommendation.disposition, AdmissionDisposition.DENY)
        self.assertIn("measurement_stale_or_future", contract.recommendation.blockers)
        self.assertIn("worker_utilization_exceeded", contract.recommendation.blockers)
        self.assertIn("queue_p95_exceeded", contract.recommendation.blockers)
        self.assertIn("quota_snapshot_stale_or_expired", contract.recommendation.blockers)
        self.assertIn("forecast_stale_or_future", contract.recommendation.blockers)

    def test_forecast_quota_and_economics_limits_deny_admission(self) -> None:
        window = self.window(validated_findings=0, model_cost_micros=900, tool_cost_micros=200)
        high = tuple(
            ForecastMetric(item.name, item.unit, 8_000, 9_000, 9_500)
            for item in self.forecast(window).metrics
        )
        contract = self.contract(
            window=window,
            attribution=self.attribution(window),
            forecast=self.forecast(window, metrics=high, confidence_basis_points=7_000),
        )
        blockers = set(contract.recommendation.blockers)
        self.assertIn("forecast_exceeds_quota_headroom", blockers)
        self.assertIn("forecast_confidence_insufficient", blockers)
        self.assertIn("assessment_cost_exceeded", blockers)
        self.assertIn("cost_per_validated_finding_unavailable", blockers)

    def test_serialized_derivations_effects_and_hashes_are_revalidated(self) -> None:
        payload = self.contract().to_dict()
        cases = []
        changed = copy.deepcopy(payload)
        changed["measurement_windows"][0]["derived"]["queue_p95_milliseconds"] = 1
        cases.append(changed)
        changed = copy.deepcopy(payload)
        changed["quota_snapshots"][0]["quotas"][0]["headroom"] = 1
        cases.append(changed)
        changed = copy.deepcopy(payload)
        changed["effects"]["billing"] = "performed"
        cases.append(changed)
        changed = copy.deepcopy(payload)
        changed["contract_sha256"] = HASH_A
        cases.append(changed)
        for case in cases:
            with self.subTest(case=cases.index(case)), self.assertRaises(CapacityEconomicsError):
                parse_contract(case)

    def test_recommendation_is_recomputed_from_bound_evidence(self) -> None:
        valid = self.contract()
        recommendation = valid.recommendation
        substituted = AdmissionRecommendation(
            as_of=recommendation.as_of,
            tenant_ref=recommendation.tenant_ref,
            assessment_ref=recommendation.assessment_ref,
            provider_ref=recommendation.provider_ref,
            region=recommendation.region,
            disposition=AdmissionDisposition.DENY,
            blockers=("substituted_blocker",),
            measurement_window_ids=recommendation.measurement_window_ids,
            attribution_id=recommendation.attribution_id,
            quota_snapshot_id=recommendation.quota_snapshot_id,
            forecast_id=recommendation.forecast_id,
            policy_id=recommendation.policy_id,
            projected_cost_micros=recommendation.projected_cost_micros,
        )
        with self.assertRaisesRegex(CapacityEconomicsError, "not derived"):
            CapacityEconomicsContract(
                valid.measurement_windows,
                valid.attributions,
                valid.quota_snapshots,
                valid.forecasts,
                valid.policy,
                substituted,
            )

    def test_forecast_bounds_horizon_and_policy_values_are_bounded(self) -> None:
        with self.assertRaisesRegex(CapacityEconomicsError, "bounds"):
            ForecastMetric("requests_per_minute", "requests", 5, 4, 6)
        window = self.window()
        with self.assertRaisesRegex(CapacityEconomicsError, "positive duration"):
            self.forecast(window, horizon_end="2026-09-20T00:15:00Z")
        with self.assertRaisesRegex(CapacityEconomicsError, "between"):
            self.policy(minimum_forecast_confidence_basis_points=10_001)

    def test_files_are_free_of_markers_and_forbidden_dash_characters(self) -> None:
        markers = (
            "generated" + " by",
            "written by" + " ai",
            "written by" + " an ai",
            "as an" + " ai",
            "chat" + "gpt",
            "co" + "dex",
            "clau" + "de",
            "gem" + "ini",
            "co-authored" + "-by",
        )
        for path in SOURCE_FILES:
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("\u2013", text, path)
            self.assertNotIn("\u2014", text, path)
            lowered = text.lower()
            for marker in markers:
                self.assertNotIn(marker, lowered, path)


if __name__ == "__main__":
    unittest.main()

"""Prospective arithmetic cannot become billing, capacity, or recovery evidence."""

from __future__ import annotations

import ast
import copy
import inspect
import json
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import sunderkey.gcp_sizing_recovery as sizing
from sunderkey.deployment_profile_contracts import build_standard_profile
from sunderkey.gcp_resource_bindings import build_gcp_resource_binding_plan
from sunderkey.gcp_sizing_recovery import (
    MAX_HORIZON_SECONDS,
    MAX_INTEGER,
    GcpSizingRecoveryError,
    GcpSizingRecoveryWorksheet,
    build_gcp_sizing_recovery_worksheet,
    split_output_token_usage,
    verify_gcp_sizing_recovery_worksheet,
)
from sunderkey.production_deployment_decision_dossier import (
    load_production_deployment_decision_dossier,
)
from sunderkey.regional_custody_contracts import TenantRegionBinding
from tests.agents.test_gcp_resource_bindings import synthetic_inputs

ROOT = Path(__file__).resolve().parents[2]
START = "2026-09-28T00:00:00Z"
END = "2026-09-28T01:00:00Z"
AS_OF = "2026-09-27T12:00:00Z"


def worksheet_inputs() -> dict:
    rates = {}
    # These are arithmetic fixtures, never quoted GCP or model-provider prices.
    for name, unit in sizing.RATE_UNITS.items():
        rates[name] = {
            "currency": "USD", "unit": unit, "unit_quantity": 3, "price_micros": 2,
            "as_of": "2026-09-27T11:00:00Z", "provenance": "synthetic_quote",
            "source_ref": "syntheticref:price-" + name, "source_sha256": "sha256:" + "a" * 64,
            "horizon_start": START, "horizon_end": END,
        }
    return {
        "as_of": AS_OF, "horizon_start": START, "horizon_end": END, "currency": "USD",
        "quantities": {
            "worker_count": 2, "worker_seconds_each": 100, "storage_bytes": 5,
            "network_bytes": 4, "input_tokens": 10, "visible_output_tokens": 5,
            "reasoning_tokens": 7,
        },
        "rates": rates,
        "ceilings": {
            "worker_count": {"unit": "workers", "limit": 4},
            "storage_bytes": {"unit": "bytes", "limit": 10},
            "network_bytes": {"unit": "bytes", "limit": 20},
            "model_tokens": {"unit": "tokens", "limit": 30},
        },
        "budget": {
            "currency": "USD", "unit": "microusd", "horizon_start": START, "horizon_end": END,
            "ceiling_micros": 1000, "stop_reserve_micros": 100,
            "evidence_reserve_micros": 200, "recovery_reserve_micros": 300,
        },
        "recovery": {
            "candidate_region": None, "rpo_seconds": 120, "rto_seconds": 300,
            "checkpoint_interval_seconds": 60, "checkpoint_lag_seconds": 10,
            "restore_bytes": 1000, "restore_bytes_per_second": 3, "startup_seconds": 10,
        },
    }


class GcpSizingRecoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.sources = {
            "dossier": load_production_deployment_decision_dossier(
                ROOT / "registry/production-deployment-decision-dossier-d014.json"
            ),
            "deployment_profile": build_standard_profile("managed_service"),
            "regional_binding": TenantRegionBinding(
                "tenantref:synthetic", "policyref:synthetic", "sha256:" + "1" * 64,
                "1.0.0", "us-west3", ("us-west3",), ("us-west3",),
                "keyref:synthetic-encryption", AS_OF,
            ),
        }
        cls.resource_plan = build_gcp_resource_binding_plan(synthetic_inputs(), **cls.sources)

    def setUp(self) -> None:
        self.inputs = worksheet_inputs()

    def build(self, raw: dict | None = None) -> GcpSizingRecoveryWorksheet:
        return build_gcp_sizing_recovery_worksheet(
            self.inputs if raw is None else raw, resource_plan=self.resource_plan, **self.sources
        )

    def verify(self, worksheet: GcpSizingRecoveryWorksheet) -> dict:
        return verify_gcp_sizing_recovery_worksheet(
            worksheet, resource_plan=self.resource_plan, **self.sources
        )

    def test_deterministic_round_trip_native_units_and_detached_summary(self) -> None:
        worksheet = self.build()
        raw = worksheet.to_dict()
        self.assertEqual(worksheet, self.build(copy.deepcopy(self.inputs)))
        self.assertEqual(worksheet, GcpSizingRecoveryWorksheet.from_json(json.dumps(raw)))
        self.assertEqual(raw["inputs"], self.inputs)
        result = self.verify(worksheet)
        self.assertEqual(result["status"], "valid_for_prospective_arithmetic_only")
        self.assertEqual(
            result["source_integrity"], "supplied_records_revalidated_not_authenticated"
        )
        self.assertEqual(set(result["effects"].values()), {"none"})
        self.inputs["quantities"]["worker_count"] = 99
        raw["summary"]["costs"]["by_category"]["fixed"] = 999
        result["summary"]["costs"]["by_category"]["workers"] = 999
        self.assertEqual(worksheet.to_dict()["summary"]["costs"]["by_category"]["fixed"], 1)
        self.assertEqual(worksheet.to_dict()["summary"]["costs"]["by_category"]["workers"], 134)

    def test_separated_costs_ceil_once_and_budget_reserves(self) -> None:
        raw = self.build().to_dict()
        costs = raw["summary"]["costs"]
        self.assertEqual(costs["by_category"], {
            "fixed": 1, "workers": 134, "storage": 4, "network": 3,
            "input": 7, "visible_output": 4, "reasoning": 5,
        })
        self.assertEqual(costs["estimated_total_micros"], 158)
        self.assertEqual(costs["known_subtotal_micros"], 158)
        self.assertEqual(set(costs["rate_age_seconds"].values()), {3600})
        budget = raw["summary"]["budget"]
        self.assertEqual(budget["reserved_total_micros"], 600)
        self.assertEqual(budget["planned_use"], 758)
        self.assertEqual(budget["headroom"], 242)
        self.assertEqual(budget["excess"], 0)
        self.assertIs(budget["within_declared_ceiling"], True)
        self.assertIn("billing_cap_enforcement_unimplemented", raw["blocker_codes"])

    def test_rate_arithmetic_can_use_exact_wide_intermediates_not_float(self) -> None:
        self.inputs["quantities"]["input_tokens"] = MAX_INTEGER
        self.inputs["quantities"]["visible_output_tokens"] = 0
        self.inputs["quantities"]["reasoning_tokens"] = 0
        self.inputs["rates"]["input"].update({
            "price_micros": MAX_INTEGER, "unit_quantity": MAX_INTEGER,
        })
        for name in sizing.RATE_UNITS:
            if name != "input":
                self.inputs["rates"][name]["price_micros"] = 0
        for name in sizing.RESERVE_FIELDS:
            self.inputs["budget"][name] = 0
        self.inputs["budget"]["ceiling_micros"] = MAX_INTEGER
        raw = self.build().to_dict()
        self.assertEqual(raw["summary"]["costs"]["by_category"]["input"], MAX_INTEGER)
        self.assertEqual(raw["summary"]["costs"]["estimated_total_micros"], MAX_INTEGER)

    def test_inclusive_output_split_prevents_reasoning_double_count(self) -> None:
        split = split_output_token_usage(total_output_tokens=12, reasoning_tokens=7)
        self.assertEqual(split, {"visible_output_tokens": 5, "reasoning_tokens": 7})
        self.inputs["quantities"].update(split)
        summary = self.build().to_dict()["summary"]
        self.assertEqual(summary["declared_capacity"]["model_tokens"]["planned_use"], 22)
        self.assertEqual(split_output_token_usage(total_output_tokens=0, reasoning_tokens=0), {
            "visible_output_tokens": 0, "reasoning_tokens": 0,
        })
        for total, reasoning in ((1, 2), (-1, 0), (True, 0), (1, 1.0), (MAX_INTEGER + 1, 0)):
            with self.subTest(total=total, reasoning=reasoning), self.assertRaises(
                GcpSizingRecoveryError
            ):
                split_output_token_usage(total_output_tokens=total, reasoning_tokens=reasoning)

    def test_missing_values_are_explicit_not_zero_defaults(self) -> None:
        self.inputs["rates"]["storage"] = None
        self.inputs["quantities"]["reasoning_tokens"] = None
        self.inputs["ceilings"]["model_tokens"]["limit"] = None
        self.inputs["budget"]["ceiling_micros"] = None
        self.inputs["budget"]["stop_reserve_micros"] = None
        self.inputs["recovery"]["rpo_seconds"] = None
        raw = self.build().to_dict()
        self.assertIsNone(raw["summary"]["costs"]["estimated_total_micros"])
        self.assertIsNone(raw["summary"]["costs"]["by_category"]["storage"])
        self.assertIsNone(raw["summary"]["costs"]["by_category"]["reasoning"])
        self.assertIsNone(raw["summary"]["budget"]["planned_use"])
        self.assertIsNone(raw["summary"]["budget"]["within_declared_ceiling"])
        for blocker in (
            "rate_missing_storage", "quantity_missing_reasoning_tokens",
            "ceiling_missing_model_tokens", "budget_ceiling_missing",
            "stop_reserve_micros_missing", "recovery_missing_rpo_seconds",
            "recovery_missing_candidate_region",
        ):
            self.assertIn(blocker, raw["blocker_codes"])

    def test_missing_rate_is_still_missing_for_an_explicit_zero_quantity(self) -> None:
        self.inputs["quantities"]["network_bytes"] = 0
        self.inputs["rates"]["network"] = None
        raw = self.build().to_dict()
        self.assertIsNone(raw["summary"]["costs"]["by_category"]["network"])
        self.assertIn("rate_missing_network", raw["blocker_codes"])

    def test_entirely_unknown_scenario_has_no_invented_sizes_costs_or_recovery(self) -> None:
        self.inputs["quantities"] = {name: None for name in sizing.QUANTITY_FIELDS}
        self.inputs["rates"] = {name: None for name in sizing.RATE_UNITS}
        for ceiling in self.inputs["ceilings"].values():
            ceiling["limit"] = None
        for name in ("ceiling_micros", *sizing.RESERVE_FIELDS):
            self.inputs["budget"][name] = None
        self.inputs["recovery"] = {name: None for name in sizing.RECOVERY_FIELDS}
        raw = self.build().to_dict()
        self.assertIsNone(raw["summary"]["costs"]["estimated_total_micros"])
        self.assertEqual(raw["summary"]["costs"]["known_subtotal_micros"], 0)
        self.assertIsNone(raw["summary"]["budget"]["within_declared_ceiling"])
        self.assertIsNone(raw["summary"]["recovery"]["transfer_seconds"])
        self.assertIsNone(raw["summary"]["recovery"]["rpo_seconds"]["within_declared_ceiling"])
        self.assertGreater(len(raw["blocker_codes"]), 30)

    def test_over_ceiling_and_over_budget_report_excess_without_authority(self) -> None:
        self.inputs["ceilings"]["worker_count"]["limit"] = 1
        self.inputs["budget"]["ceiling_micros"] = 700
        raw = self.build().to_dict()
        self.assertEqual(raw["summary"]["declared_capacity"]["worker_count"]["excess"], 1)
        self.assertEqual(raw["summary"]["budget"]["excess"], 58)
        self.assertEqual(raw["summary"]["budget"]["headroom"], 0)
        self.assertIn("declared_budget_exceeded", raw["blocker_codes"])
        self.assertIn("declared_ceiling_exceeded_worker_count", raw["blocker_codes"])
        self.assertEqual(raw["effects"]["authorization"], "none")

    def test_zero_reserves_do_not_claim_protected_stop_evidence_or_recovery(self) -> None:
        for name in sizing.RESERVE_FIELDS:
            self.inputs["budget"][name] = 0
        raw = self.build().to_dict()
        for name in sizing.RESERVE_FIELDS:
            self.assertIn(name + "_not_positive", raw["blocker_codes"])

    def test_recovery_is_conditional_arithmetic_not_signed_proof(self) -> None:
        raw = self.build().to_dict()
        recovery = raw["summary"]["recovery"]
        self.assertEqual(recovery["rpo_seconds"]["planned_use"], 70)
        self.assertIs(recovery["rpo_seconds"]["within_declared_ceiling"], True)
        self.assertEqual(recovery["transfer_seconds"], 334)
        self.assertEqual(recovery["rto_seconds"]["planned_use"], 344)
        self.assertEqual(recovery["rto_seconds"]["excess"], 44)
        self.assertIn("declared_restore_model_exceeds_rto", raw["blocker_codes"])
        self.assertIsNone(recovery["candidate_region"])
        self.assertEqual(recovery["observed_recovery_evidence"], "none")
        self.inputs["recovery"].update({"candidate_region": "us-west1", "rto_seconds": 1000})
        selected = self.build().to_dict()
        self.assertEqual(
            selected["summary"]["recovery"]["candidate_status"], "unselected_unverified"
        )
        self.assertIn("recovery_location_not_selected_or_verified", selected["blocker_codes"])
        self.assertIn("signed_restoration_observations_required", selected["blocker_codes"])
        self.assertIsNone(self.resource_plan.to_dict()["recovery_region"])

    def test_native_aliases_unsupported_types_and_negative_values_reject(self) -> None:
        class IntSubclass(int):
            pass

        class StringSubclass(str):
            pass

        class DictSubclass(dict):
            pass

        mutations = (
            lambda raw: raw["quantities"].update({"worker_count": True}),
            lambda raw: raw["quantities"].update({"storage_bytes": 1.0}),
            lambda raw: raw["quantities"].update({"input_tokens": -1}),
            lambda raw: raw["quantities"].update({"network_bytes": IntSubclass(1)}),
            lambda raw: raw["rates"]["fixed"].update({"unit_quantity": 0}),
            lambda raw: raw["rates"]["fixed"].update({"price_micros": False}),
            lambda raw: raw["rates"]["fixed"].update({"provenance": []}),
            lambda raw: raw["rates"]["fixed"].update({"source_ref": 1}),
            lambda raw: raw["rates"]["fixed"].update({"source_ref": " "}),
            lambda raw: raw["rates"]["fixed"].update({"source_ref": StringSubclass("quote")}),
            lambda raw: raw["rates"]["fixed"].update({"source_sha256": None}),
            lambda raw: raw["recovery"].update({"restore_bytes_per_second": 0}),
            lambda raw: raw["recovery"].update({"rpo_seconds": 0}),
            lambda raw: raw["recovery"].update({"candidate_region": "us-west3-a"}),
            lambda raw: raw["budget"].update({"stop_reserve_micros": float("nan")}),
            lambda raw: raw.update({"currency": "EUR"}),
            lambda raw: raw.update({"quantities": DictSubclass(raw["quantities"])}),
        )
        for mutation in mutations:
            raw = copy.deepcopy(self.inputs)
            mutation(raw)
            with self.subTest(mutation=mutation), self.assertRaises(GcpSizingRecoveryError):
                self.build(raw)

    def test_closed_fields_and_unit_mismatches_reject(self) -> None:
        for mutation in (
            lambda raw: raw.update({"credentials": "forbidden"}),
            lambda raw: raw["rates"]["fixed"].update({"provider_verified": True}),
            lambda raw: raw["quantities"].pop("storage_bytes"),
            lambda raw: raw["rates"].pop("reasoning"),
            lambda raw: raw["rates"]["network"].update({"unit": "gigabyte"}),
            lambda raw: raw["ceilings"]["storage_bytes"].update({"unit": "gibibytes"}),
            lambda raw: raw["budget"].update({"unit": "USD"}),
            lambda raw: raw["recovery"].update({"backup_verified": True}),
        ):
            raw = copy.deepcopy(self.inputs)
            mutation(raw)
            with self.subTest(mutation=mutation), self.assertRaises(GcpSizingRecoveryError):
                self.build(raw)

    def test_exact_horizons_chronology_and_bounds_reject(self) -> None:
        for mutation in (
            lambda raw: raw.update({"horizon_end": START}),
            lambda raw: raw.update({"horizon_start": "2026-09-27T00:00:00Z"}),
            lambda raw: raw.update({"horizon_end": "2028-01-01T00:00:00Z"}),
            lambda raw: raw.update({"as_of": "2026-09-27T12:00:00+00:00"}),
            lambda raw: raw["rates"]["fixed"].update({"horizon_end": START}),
            lambda raw: raw["rates"]["fixed"].update({"as_of": "2026-09-27T13:00:00Z"}),
            lambda raw: raw["rates"]["fixed"].update({"currency": "EUR"}),
            lambda raw: raw["budget"].update({"horizon_start": AS_OF}),
            lambda raw: raw["quantities"].update({"worker_seconds_each": 3601}),
        ):
            raw = copy.deepcopy(self.inputs)
            mutation(raw)
            with self.subTest(mutation=mutation), self.assertRaises(GcpSizingRecoveryError):
                self.build(raw)
        self.assertEqual(MAX_HORIZON_SECONDS, 366 * 86400)

    def test_inputs_products_totals_and_recovery_overflow_reject(self) -> None:
        mutations = (
            lambda raw: raw["quantities"].update({"worker_count": MAX_INTEGER + 1}),
            lambda raw: raw["quantities"].update({"worker_count": MAX_INTEGER}),
            lambda raw: raw["rates"]["workers"].update({"price_micros": MAX_INTEGER}),
            lambda raw: raw["rates"]["fixed"].update({
                "price_micros": MAX_INTEGER, "unit_quantity": 1,
            }),
            lambda raw: raw["budget"].update({"stop_reserve_micros": MAX_INTEGER}),
            lambda raw: raw["budget"].update({
                "stop_reserve_micros": MAX_INTEGER, "evidence_reserve_micros": MAX_INTEGER,
                "recovery_reserve_micros": None,
            }),
            lambda raw: raw["recovery"].update({"checkpoint_interval_seconds": MAX_INTEGER}),
            lambda raw: raw["recovery"].update({
                "restore_bytes": MAX_INTEGER, "restore_bytes_per_second": 1,
            }),
        )
        for mutation in mutations:
            raw = copy.deepcopy(self.inputs)
            mutation(raw)
            with self.subTest(mutation=mutation), self.assertRaises(GcpSizingRecoveryError):
                self.build(raw)

    def test_tampered_derived_metadata_and_wire_primitives_reject(self) -> None:
        positive = self.build().to_dict()
        for mutation in (
            lambda raw: raw.update({"schema_version": True}),
            lambda raw: raw.update({"schema_version": 1.0}),
            lambda raw: raw["effects"].update({"billing": "enforced"}),
            lambda raw: raw["summary"]["costs"].update({"estimated_total_micros": 1}),
            lambda raw: raw["summary"]["budget"].update({"within_declared_ceiling": 1}),
            lambda raw: raw["summary"]["recovery"].update({"candidate_status": "selected"}),
            lambda raw: raw.update({"blocker_codes": []}),
            lambda raw: raw.update({"worksheet_sha256": "sha256:" + "0" * 64}),
            lambda raw: raw.update({"identity_assurance": "authenticated"}),
        ):
            raw = copy.deepcopy(positive)
            mutation(raw)
            with self.subTest(mutation=mutation), self.assertRaises(GcpSizingRecoveryError):
                GcpSizingRecoveryWorksheet.from_dict(raw)

    def test_duplicate_keys_nonfinite_and_noncanonical_wrapper_reject(self) -> None:
        worksheet = self.build()
        text = worksheet.document_json
        duplicate = text.replace('"schema_version":1', '"schema_version":1,"schema_version":1')
        for value in (duplicate, '{"value":NaN}', '{"value":Infinity}', text + " "):
            with self.subTest(value=value[:50]), self.assertRaises(GcpSizingRecoveryError):
                if value == text + " ":
                    GcpSizingRecoveryWorksheet(value)
                else:
                    GcpSizingRecoveryWorksheet.from_json(value)

    def test_shared_native_graph_is_bounded_before_input_serialization(self) -> None:
        graph: list = ["synthetic"]
        for _ in range(5):
            graph = [graph] * 128
        self.inputs["quantities"] = graph
        encode = json.dumps

        def bounded_encode(value, *args, **kwargs):
            if value is self.inputs:
                self.fail("Oversized shared input reached JSON serialization")
            return encode(value, *args, **kwargs)

        with patch("sunderkey.gcp_resource_bindings.json.dumps", side_effect=bounded_encode):
            with self.assertRaises(GcpSizingRecoveryError):
                self.build()

    def test_exact_source_revalidation_and_record_substitution_fail(self) -> None:
        worksheet = self.build()
        sources = dict(self.sources)
        sources["regional_binding"] = replace(
            sources["regional_binding"], effective_at="2026-09-27T13:00:00Z"
        )
        with self.assertRaises(GcpSizingRecoveryError):
            verify_gcp_sizing_recovery_worksheet(
                worksheet, resource_plan=self.resource_plan, **sources
            )
        changed = synthetic_inputs()
        changed["projects"][0]["project_number"] = "234567890123"
        alternate = build_gcp_resource_binding_plan(changed, **self.sources)
        with self.assertRaises(GcpSizingRecoveryError):
            verify_gcp_sizing_recovery_worksheet(worksheet, resource_plan=alternate, **self.sources)
        with self.assertRaises(GcpSizingRecoveryError):
            build_gcp_sizing_recovery_worksheet(self.inputs, resource_plan={}, **self.sources)

    def test_late_wrapper_mutation_and_subclass_consumer_reject(self) -> None:
        worksheet = self.build()
        object.__setattr__(worksheet, "document_json", worksheet.document_json + " ")
        with self.assertRaises(GcpSizingRecoveryError):
            self.verify(worksheet)

        class WorksheetSubclass(GcpSizingRecoveryWorksheet):
            pass

        with self.assertRaises(GcpSizingRecoveryError):
            self.verify(WorksheetSubclass(self.build().document_json))

    def test_no_metric_forecast_recovery_evidence_network_or_storage_surface(self) -> None:
        tree = ast.parse(inspect.getsource(sizing))
        imports = {
            alias.name.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.Import)
            for alias in node.names
        } | {
            node.module.split(".")[0] for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and not node.level and node.module
        }
        self.assertFalse(imports & {"google", "requests", "http", "urllib", "socket", "subprocess"})
        calls = {
            node.func.id for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        self.assertFalse(calls & {
            "MeasurementWindow", "ProviderQuotaSnapshot", "DemandForecast", "RecoveryObjective",
            "BackupManifest", "ObservedRestorationResult", "assess_recovery_readiness", "open",
        })
        methods = {
            node.func.attr for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        }
        self.assertFalse(methods & {
            "read_text", "write_text", "read_bytes", "write_bytes", "getenv",
        })


if __name__ == "__main__":
    unittest.main()

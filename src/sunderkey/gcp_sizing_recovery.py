"""Prospective GCP sizing arithmetic, never billing or recovery evidence."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .deployment_profile_contracts import DeploymentProfile
from .gcp_resource_bindings import (
    GcpResourceBindingError,
    GcpResourceBindingPlan,
    _canonical as _planning_canonical,
    parse_gcp_planning_json,
    verify_gcp_resource_binding_plan,
)
from .production_deployment_decision_dossier import ProductionDeploymentDecisionDossier
from .regional_custody_contracts import TenantRegionBinding

DOMAIN = "sunderkey.gcp-sizing-recovery-worksheet.v1"
MAX_INTEGER = 2**63 - 1
MAX_HORIZON_SECONDS = 366 * 86400
RATE_UNITS = {
    "fixed": "fixed_horizon",
    "workers": "worker_second",
    "storage": "storage_byte_horizon",
    "network": "network_byte",
    "input": "input_token",
    "visible_output": "visible_output_token",
    "reasoning": "reasoning_token",
}
QUANTITY_FIELDS = {
    "worker_count", "worker_seconds_each", "storage_bytes", "network_bytes",
    "input_tokens", "visible_output_tokens", "reasoning_tokens",
}
CEILING_UNITS = {
    "worker_count": "workers",
    "storage_bytes": "bytes",
    "network_bytes": "bytes",
    "model_tokens": "tokens",
}
RECOVERY_FIELDS = {
    "candidate_region", "rpo_seconds", "rto_seconds", "checkpoint_interval_seconds",
    "checkpoint_lag_seconds", "restore_bytes", "restore_bytes_per_second", "startup_seconds",
}
RESERVE_FIELDS = ("stop_reserve_micros", "evidence_reserve_micros", "recovery_reserve_micros")
EFFECTS = {
    "authorization": "none", "backup": "none", "billing": "none",
    "credential_access": "none", "deployment": "none", "metric_collection": "none",
    "network": "none", "persistence": "none", "provider_calls": "none",
    "qualification": "none", "restore": "none", "scaling": "none", "target_action": "none",
}
EXTERNAL_BLOCKERS = {
    "billing_cap_enforcement_unimplemented",
    "measured_capacity_and_quota_evidence_required",
    "provider_prices_and_billable_units_unverified",
    "recovery_location_not_selected_or_verified",
    "signed_recovery_objective_and_backup_evidence_required",
    "signed_restoration_observations_required",
}
_UTC = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_REGION = re.compile(r"[a-z]+-[a-z]+[1-9][0-9]{0,2}")
_INPUT_FIELDS = {
    "as_of", "horizon_start", "horizon_end", "currency", "quantities", "rates",
    "ceilings", "budget", "recovery",
}


class GcpSizingRecoveryError(ValueError):
    """Invalid prospective inputs, content address, or exact source binding."""


def _canonical(value: Any) -> str:
    try:
        return _planning_canonical(value)
    except GcpResourceBindingError as exc:
        raise GcpSizingRecoveryError(
            "Worksheet JSON contains unsupported values or bounds"
        ) from exc


def _exact(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if (
        type(value) is not dict
        or any(type(key) is not str for key in value)
        or set(value) != fields
    ):
        raise GcpSizingRecoveryError(f"{label} fields are invalid")
    return value


def _integer(value: Any, label: str, *, positive: bool = False) -> int:
    if type(value) is not int or not (1 if positive else 0) <= value <= MAX_INTEGER:
        raise GcpSizingRecoveryError(f"{label} must be a bounded native integer")
    return value


def _optional_integer(value: Any, label: str, *, positive: bool = False) -> int | None:
    return None if value is None else _integer(value, label, positive=positive)


def _instant(value: Any) -> datetime:
    if type(value) is not str or _UTC.fullmatch(value) is None:
        raise GcpSizingRecoveryError("Worksheet time must be canonical UTC")
    try:
        return datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise GcpSizingRecoveryError("Worksheet time is invalid") from exc


def _horizon(value: dict[str, Any], inputs: dict[str, Any]) -> None:
    if (
        value["currency"] != "USD"
        or value["horizon_start"] != inputs["horizon_start"]
        or value["horizon_end"] != inputs["horizon_end"]
    ):
        raise GcpSizingRecoveryError("Currency or exact pricing/budget horizon does not match")


def _validate_inputs(raw: Any) -> dict[str, Any]:
    value = _exact(raw, _INPUT_FIELDS, "worksheet input")
    captured = json.loads(_canonical(value))
    as_of = _instant(captured["as_of"])
    start = _instant(captured["horizon_start"])
    end = _instant(captured["horizon_end"])
    seconds = int((end - start).total_seconds())
    if as_of > start or not 1 <= seconds <= MAX_HORIZON_SECONDS or captured["currency"] != "USD":
        raise GcpSizingRecoveryError("Prospective horizon or supported currency is invalid")
    quantities = _exact(captured["quantities"], QUANTITY_FIELDS, "quantities")
    for key, amount in quantities.items():
        _optional_integer(amount, key)
    worker_seconds = quantities["worker_seconds_each"]
    if worker_seconds is not None and worker_seconds > seconds:
        raise GcpSizingRecoveryError("Per-worker runtime exceeds the explicit horizon")
    rates = _exact(captured["rates"], set(RATE_UNITS), "rates")
    for name, rate in rates.items():
        if rate is None:
            continue
        _exact(rate, {
            "currency", "unit", "unit_quantity", "price_micros", "as_of", "provenance",
            "source_ref", "source_sha256", "horizon_start", "horizon_end",
        }, "rate")
        _horizon(rate, captured)
        if rate["unit"] != RATE_UNITS[name]:
            raise GcpSizingRecoveryError("Rate unit does not match its cost category")
        _integer(rate["unit_quantity"], "rate unit_quantity", positive=True)
        _integer(rate["price_micros"], "rate price_micros")
        if _instant(rate["as_of"]) > as_of:
            raise GcpSizingRecoveryError("Rate observation is later than worksheet as_of")
        if type(rate["provenance"]) is not str or rate["provenance"] not in {
            "operator_supplied_quote", "synthetic_quote",
        }:
            raise GcpSizingRecoveryError("Rate provenance is unsupported")
        if (
            type(rate["source_ref"]) is not str
            or not 1 <= len(rate["source_ref"]) <= 2048
            or rate["source_ref"].strip() != rate["source_ref"]
        ):
            raise GcpSizingRecoveryError("Rate source reference is missing or too long")
        if (
            type(rate["source_sha256"]) is not str
            or _DIGEST.fullmatch(rate["source_sha256"]) is None
        ):
            raise GcpSizingRecoveryError("Rate source digest is invalid")
    ceilings = _exact(captured["ceilings"], set(CEILING_UNITS), "ceilings")
    for name, declaration in ceilings.items():
        _exact(declaration, {"unit", "limit"}, "ceiling")
        if declaration["unit"] != CEILING_UNITS[name]:
            raise GcpSizingRecoveryError("Ceiling unit does not match its dimension")
        _optional_integer(declaration["limit"], "ceiling limit")
    budget = _exact(captured["budget"], {
        "currency", "unit", "horizon_start", "horizon_end", "ceiling_micros", *RESERVE_FIELDS,
    }, "budget")
    _horizon(budget, captured)
    if budget["unit"] != "microusd":
        raise GcpSizingRecoveryError("Budget unit must be microusd")
    for name in ("ceiling_micros", *RESERVE_FIELDS):
        _optional_integer(budget[name], name)
    recovery = _exact(captured["recovery"], RECOVERY_FIELDS, "recovery")
    candidate = recovery["candidate_region"]
    if candidate is not None and (
        type(candidate) is not str or _REGION.fullmatch(candidate) is None
    ):
        raise GcpSizingRecoveryError("Recovery candidate must be an explicit region-form name")
    for name in RECOVERY_FIELDS - {"candidate_region"}:
        _optional_integer(recovery[name], name, positive=name in {
            "rpo_seconds", "rto_seconds", "checkpoint_interval_seconds", "restore_bytes_per_second",
        })
    return captured


def _bounded_result(value: int) -> int:
    if not 0 <= value <= MAX_INTEGER:
        raise GcpSizingRecoveryError("Derived arithmetic exceeds the signed 64-bit bound")
    return value


def split_output_token_usage(*, total_output_tokens: int, reasoning_tokens: int) -> dict[str, int]:
    """Split declared inclusive output usage into disjoint counts without a provider call."""
    total = _integer(total_output_tokens, "total_output_tokens")
    reasoning = _integer(reasoning_tokens, "reasoning_tokens")
    if reasoning > total:
        raise GcpSizingRecoveryError("Reasoning tokens cannot exceed inclusive total output tokens")
    return {"visible_output_tokens": total - reasoning, "reasoning_tokens": reasoning}


def _sum(values: list[int | None]) -> int | None:
    known = _bounded_result(sum(value for value in values if value is not None))
    return None if any(value is None for value in values) else known


def _product(left: int | None, right: int | None) -> int | None:
    return None if left is None or right is None else _bounded_result(left * right)


def _comparison(limit: int | None, used: int | None) -> dict[str, Any]:
    known = limit is not None and used is not None
    return {
        "declared_limit": limit,
        "planned_use": used,
        "within_declared_ceiling": None if not known else used <= limit,
        "headroom": None if not known else max(0, limit - used),
        "excess": None if not known else max(0, used - limit),
    }


def _derive(inputs: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    blockers = set(EXTERNAL_BLOCKERS)
    q = inputs["quantities"]
    horizon_seconds = int((_instant(inputs["horizon_end"]) - _instant(
        inputs["horizon_start"]
    )).total_seconds())
    quantities = {
        "fixed": 1,
        "workers": _product(q["worker_count"], q["worker_seconds_each"]),
        "storage": q["storage_bytes"],
        "network": q["network_bytes"],
        "input": q["input_tokens"],
        "visible_output": q["visible_output_tokens"],
        "reasoning": q["reasoning_tokens"],
    }
    for name, amount in q.items():
        if amount is None:
            blockers.add("quantity_missing_" + name)
    costs: dict[str, int | None] = {}
    ages: dict[str, int | None] = {}
    for name, amount in quantities.items():
        rate = inputs["rates"][name]
        if rate is None:
            blockers.add("rate_missing_" + name)
        costs[name] = None if rate is None or amount is None else _bounded_result(
            (amount * rate["price_micros"] + rate["unit_quantity"] - 1) // rate["unit_quantity"]
        )
        ages[name] = None if rate is None else int((_instant(inputs["as_of"]) - _instant(
            rate["as_of"]
        )).total_seconds())
    known_cost = _bounded_result(sum(cost for cost in costs.values() if cost is not None))
    total_cost = _sum(list(costs.values()))
    model_tokens = _sum([q["input_tokens"], q["visible_output_tokens"], q["reasoning_tokens"]])
    planned = {**q, "model_tokens": model_tokens}
    capacity = {}
    for name, declaration in inputs["ceilings"].items():
        capacity[name] = {"unit": CEILING_UNITS[name], **_comparison(
            declaration["limit"], planned[name]
        )}
        if declaration["limit"] is None:
            blockers.add("ceiling_missing_" + name)
        elif capacity[name]["within_declared_ceiling"] is False:
            blockers.add("declared_ceiling_exceeded_" + name)
    budget = inputs["budget"]
    reserves = {name: budget[name] for name in RESERVE_FIELDS}
    for name, amount in reserves.items():
        if amount is None:
            blockers.add(name + "_missing")
        elif amount == 0:
            blockers.add(name + "_not_positive")
    reserved = _sum(list(reserves.values()))
    planned_with_reserves = _sum([total_cost, reserved])
    budget_comparison = _comparison(budget["ceiling_micros"], planned_with_reserves)
    if budget["ceiling_micros"] is None:
        blockers.add("budget_ceiling_missing")
    elif budget_comparison["within_declared_ceiling"] is False:
        blockers.add("declared_budget_exceeded")
    recovery = inputs["recovery"]
    for name, amount in recovery.items():
        if amount is None:
            blockers.add("recovery_missing_" + name)
    loss_bound = _sum([recovery["checkpoint_interval_seconds"], recovery["checkpoint_lag_seconds"]])
    size, throughput = recovery["restore_bytes"], recovery["restore_bytes_per_second"]
    transfer = None if size is None or throughput is None else _bounded_result(
        (size + throughput - 1) // throughput
    )
    restoration = _sum([transfer, recovery["startup_seconds"]])
    rpo_comparison = _comparison(recovery["rpo_seconds"], loss_bound)
    rto_comparison = _comparison(recovery["rto_seconds"], restoration)
    if rpo_comparison["within_declared_ceiling"] is False:
        blockers.add("declared_checkpoint_model_exceeds_rpo")
    if rto_comparison["within_declared_ceiling"] is False:
        blockers.add("declared_restore_model_exceeds_rto")
    return {
        "horizon_seconds": horizon_seconds,
        "costs": {
            "unit": "microusd", "by_category": costs,
            "known_subtotal_micros": known_cost, "estimated_total_micros": total_cost,
            "rate_age_seconds": ages,
            "rounding": "ceil_each_category_once",
        },
        "declared_capacity": capacity,
        "budget": {
            "unit": "microusd", "reserves": reserves, "reserved_total_micros": reserved,
            **budget_comparison,
        },
        "recovery": {
            "candidate_region": recovery["candidate_region"],
            "candidate_status": "unselected_unverified",
            "planning_model": "cadence_plus_lag_and_transfer_plus_startup",
            "transfer_seconds": transfer, "rpo_seconds": rpo_comparison,
            "rto_seconds": rto_comparison,
            "observed_recovery_evidence": "none",
        },
    }, sorted(blockers)


def _reference(value: Any, prefix: str) -> dict[str, str]:
    ref = _exact(value, {"id", "sha256"}, "source reference")
    digest = ref["sha256"]
    if type(digest) is not str or _DIGEST.fullmatch(digest) is None:
        raise GcpSizingRecoveryError("Source digest is invalid")
    if type(ref["id"]) is not str or ref["id"] != prefix + "-" + digest[7:39].upper():
        raise GcpSizingRecoveryError("Source identity and digest do not agree")
    return dict(ref)


def _document(inputs: Any, resource: Any, sources: Any) -> dict[str, Any]:
    inputs = _validate_inputs(inputs)
    resource = _reference(resource, "GRP")
    source_values = _exact(sources, {
        "d014_dossier", "deployment_profile", "regional_binding",
    }, "source bindings")
    bindings = {name: _reference(source_values[name], prefix) for name, prefix in (
        ("d014_dossier", "PDD"), ("deployment_profile", "DPC"), ("regional_binding", "TRB"),
    )}
    summary, blockers = _derive(inputs)
    body = {
        "kind": DOMAIN, "schema_version": 1, "inputs": inputs,
        "resource_plan": resource, "source_bindings": bindings, "summary": summary,
        "blocker_codes": blockers, "status": "prospective_arithmetic_only",
        "identity_assurance": "operator_asserted_unsigned",
        "source_integrity": "requires_exact_source_revalidation_at_use",
        "effects": dict(EFFECTS),
    }
    digest = "sha256:" + hashlib.sha256(_canonical({"domain": DOMAIN, "worksheet": body}).encode(
        "ascii"
    )).hexdigest()
    return {**body, "worksheet_id": "GSW-" + digest[7:39].upper(), "worksheet_sha256": digest}


@dataclass(frozen=True, slots=True)
class GcpSizingRecoveryWorksheet:
    """Detached unsigned arithmetic record, not trusted price or recovery proof."""

    document_json: str

    def __post_init__(self) -> None:
        self.to_dict()

    @classmethod
    def from_dict(cls, raw: Any) -> GcpSizingRecoveryWorksheet:
        return cls(_canonical(raw))

    @classmethod
    def from_json(cls, text: str) -> GcpSizingRecoveryWorksheet:
        try:
            return cls.from_dict(parse_gcp_planning_json(text))
        except GcpResourceBindingError as exc:
            raise GcpSizingRecoveryError("Worksheet JSON failed bounded native parsing") from exc

    def to_dict(self) -> dict[str, Any]:
        try:
            raw = parse_gcp_planning_json(self.document_json)
        except GcpResourceBindingError as exc:
            raise GcpSizingRecoveryError("Worksheet wrapper failed bounded native parsing") from exc
        _exact(raw, {
            "kind", "schema_version", "inputs", "resource_plan", "source_bindings", "summary",
            "blocker_codes", "status", "identity_assurance", "source_integrity", "effects",
            "worksheet_id", "worksheet_sha256",
        }, "worksheet")
        expected = _document(raw["inputs"], raw["resource_plan"], raw["source_bindings"])
        if _canonical(raw) != _canonical(expected) or self.document_json != _canonical(raw):
            raise GcpSizingRecoveryError(
                "Worksheet metadata, arithmetic or content address is invalid"
            )
        return raw


def _resource_snapshot(
    resource_plan: GcpResourceBindingPlan,
    dossier: ProductionDeploymentDecisionDossier,
    deployment_profile: DeploymentProfile,
    regional_binding: TenantRegionBinding,
) -> tuple[dict[str, Any], dict[str, Any]]:
    try:
        assessment = verify_gcp_resource_binding_plan(
            resource_plan, dossier=dossier, deployment_profile=deployment_profile,
            regional_binding=regional_binding,
        )
        return resource_plan.to_dict(), assessment
    except (ValueError, TypeError, AttributeError) as exc:
        raise GcpSizingRecoveryError(
            "Resource plan or exact supplied sources failed revalidation"
        ) from exc


def build_gcp_sizing_recovery_worksheet(
    inputs: dict[str, Any],
    *,
    resource_plan: GcpResourceBindingPlan,
    dossier: ProductionDeploymentDecisionDossier,
    deployment_profile: DeploymentProfile,
    regional_binding: TenantRegionBinding,
) -> GcpSizingRecoveryWorksheet:
    """Calculate only operator-declared arithmetic after exact planning-source checks."""
    snapshot, _ = _resource_snapshot(resource_plan, dossier, deployment_profile, regional_binding)
    return GcpSizingRecoveryWorksheet.from_dict(_document(
        inputs, {"id": snapshot["plan_id"], "sha256": snapshot["plan_sha256"]},
        snapshot["source_bindings"],
    ))


def verify_gcp_sizing_recovery_worksheet(
    worksheet: GcpSizingRecoveryWorksheet,
    *,
    resource_plan: GcpResourceBindingPlan,
    dossier: ProductionDeploymentDecisionDossier,
    deployment_profile: DeploymentProfile,
    regional_binding: TenantRegionBinding,
) -> dict[str, Any]:
    """Revalidate supplied planning records, never admit work or verify live recovery."""
    if type(worksheet) is not GcpSizingRecoveryWorksheet:
        raise GcpSizingRecoveryError("The exact worksheet family is required")
    raw = worksheet.to_dict()
    snapshot, resource_assessment = _resource_snapshot(
        resource_plan, dossier, deployment_profile, regional_binding
    )
    expected = _document(
        raw["inputs"], {"id": snapshot["plan_id"], "sha256": snapshot["plan_sha256"]},
        snapshot["source_bindings"],
    )
    if _canonical(raw) != _canonical(expected):
        raise GcpSizingRecoveryError("Worksheet does not bind the exact supplied source records")
    return {
        "status": "valid_for_prospective_arithmetic_only",
        "worksheet_id": raw["worksheet_id"], "worksheet_sha256": raw["worksheet_sha256"],
        "source_integrity": "supplied_records_revalidated_not_authenticated",
        "summary": raw["summary"],
        "blocker_codes": sorted(set(raw["blocker_codes"]) | set(
            resource_assessment["blocker_codes"]
        )),
        "effects": dict(EFFECTS),
    }

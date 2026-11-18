"""Compare a supplied spot price with a bounded time-weighted reference."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "defi_supplied_spot_twap_deviation"
PROFILE_ID = "AOE-GB-D10-S03"
CAPABILITY_ID = "army.gb.d10.s03"
VECTOR_ID = "AV-GB-D10-S03-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D10-S03"
WAVE_ID = "IW2-003"
COMMANDER_ID = "AOE-GB-D10-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:9c3a9bbd5813a7ce7d41d2413131b4b31c9ba1b3c64c50f410b0639a2ddeb0f4"
DOMAIN = "sunderkey.offline-oracle-twap-deviation.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
EFFECTS = {
    key: "none"
    for key in (
        "authority",
        "execution",
        "filesystem",
        "network",
        "process",
        "provider",
        "credentials",
        "target_interaction",
        "finding_publication",
        "qualification",
    )
}


class OracleTwapDeviationError(ValueError):
    """A supplied oracle price comparison or replay is invalid."""


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {
            "schema_version",
            "source_id",
            "market_id",
            "spot_price_micro",
            "minimum_deviation_basis_points",
            "sequence_complete",
            "same_market",
            "reference_independent",
            "twap_samples",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise OracleTwapDeviationError("Unsupported model version")
    for key in ("source_id", "market_id"):
        core.identifier(model[key], key)
    spot = model["spot_price_micro"]
    if type(spot) is not int or not 1 <= spot <= 1_000_000_000:
        raise OracleTwapDeviationError("Spot price must be bounded positive micro-units")
    limit = model["minimum_deviation_basis_points"]
    if type(limit) is not int or not 0 <= limit <= 10_000:
        raise OracleTwapDeviationError("Deviation threshold must be integer basis points")
    for key in ("sequence_complete", "same_market", "reference_independent"):
        core.boolean(model[key], key)
    samples = core.bounded_list(model["twap_samples"], 32, "TWAP samples")
    if not samples:
        raise OracleTwapDeviationError("At least one TWAP sample is required")
    seen: set[str] = set()
    for item in samples:
        row = core.exact(item, {"sample_id", "price_micro", "duration_seconds"}, "sample")
        sample_id = core.identifier(row["sample_id"], "sample ID")
        if sample_id in seen:
            raise OracleTwapDeviationError("Duplicate sample ID")
        seen.add(sample_id)
        price = row["price_micro"]
        duration = row["duration_seconds"]
        if type(price) is not int or not 1 <= price <= 1_000_000_000:
            raise OracleTwapDeviationError("Sample price must be bounded positive micro-units")
        if type(duration) is not int or not 1 <= duration <= 3_600:
            raise OracleTwapDeviationError("Sample duration must be bounded positive seconds")
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, model_text = _model(value)
    duration = sum(row["duration_seconds"] for row in model["twap_samples"])
    weighted_sum = sum(
        row["price_micro"] * row["duration_seconds"] for row in model["twap_samples"]
    )
    spot_total = model["spot_price_micro"] * duration
    numerator = abs(spot_total - weighted_sum) * 10_000
    denominator = weighted_sum
    premises = all(
        model[key] for key in ("sequence_complete", "same_market", "reference_independent")
    )
    exceeds = numerator > model["minimum_deviation_basis_points"] * denominator
    disposition = (
        "unknown"
        if not premises
        else "candidate_declared_spot_twap_deviation"
        if exceeds
        else "within_declared_deviation_limit"
    )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(model_text.encode("ascii")),
        "market_id": model["market_id"],
        "sample_count": len(model["twap_samples"]),
        "duration_seconds": duration,
        "twap_weighted_price_numerator": weighted_sum,
        "twap_weighted_price_denominator": duration,
        "relative_deviation_numerator": numerator,
        "relative_deviation_denominator": denominator,
        "disposition": disposition,
        "candidate_count": int(disposition.startswith("candidate_")),
        "unknown_count": int(disposition == "unknown"),
        "source_authenticated": False,
        "oracle_queried": False,
        "flash_loan_simulated": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Spot and sample prices, time windows and market identity are caller-supplied.",
            "The calculation assumes a continuous complete sequence and independent reference.",
            "Deviation does not prove oracle manipulation, profit or flash-loan feasibility.",
            "No pool, chain, transaction, oracle or target is queried.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="OTD-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class OracleTwapDeviationReport:
    """Unsigned price projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise OracleTwapDeviationError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> OracleTwapDeviationReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_oracle_twap(model: Any) -> OracleTwapDeviationReport:
    return OracleTwapDeviationReport._owned(_derive(model))


def verify_supplied_oracle_twap(report: Any, *, model: Any) -> OracleTwapDeviationReport:
    if type(report) is not OracleTwapDeviationReport:
        raise OracleTwapDeviationError("Exact oracle projection wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise OracleTwapDeviationError("Report differs from separate original model")
    return OracleTwapDeviationReport._owned(expected)


def verify_supplied_oracle_twap_bytes(
    report_bytes: bytes, *, model: Any
) -> OracleTwapDeviationReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise OracleTwapDeviationError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise OracleTwapDeviationError("Exported report differs from original replay")
    return OracleTwapDeviationReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-oracle-prices",
        "market_id": "pool-one",
        "spot_price_micro": 1_500_000,
        "minimum_deviation_basis_points": 1_000,
        "sequence_complete": True,
        "same_market": True,
        "reference_independent": True,
        "twap_samples": [
            {"sample_id": "window-one", "price_micro": 1_000_000, "duration_seconds": 60},
            {"sample_id": "window-two", "price_micro": 1_000_000, "duration_seconds": 60},
        ],
    }

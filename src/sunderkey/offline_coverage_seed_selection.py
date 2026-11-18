"""Rank supplied fuzz corpus coverage bitmaps without executing a target."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "exploit_supplied_coverage_seed_selection"
PROFILE_ID = "AOE-GE-D21-S13"
CAPABILITY_ID = "army.ge.d21.s13"
VECTOR_ID = "AV-GE-D21-S13-01"
WORK_PACKAGE_ID = "IWP2-AOE-GE-D21-S13"
WAVE_ID = "IW2-025"
COMMANDER_ID = "AOE-GE-D21-CMD"
GROUP_OWNER_ID = "AOE-HQ-07"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:9284e16949034b88ce064d124a27f99522a9bdd3b59593cc721040328ca64426"
DOMAIN = "sunderkey.offline-coverage-seed-selection.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
MAX_SEEDS = 32
MAX_WIDTH_BITS = 2048
HEX = re.compile(r"[0-9a-f]+\Z")
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process",
        "provider", "credentials", "target_interaction",
        "finding_publication", "qualification",
    )
}


class CoverageSeedSelectionError(ValueError):
    """The supplied coverage model or original-model replay is invalid."""


def _bits(value: Any, width: int, label: str) -> int:
    if (
        type(value) is not str
        or len(value) != width // 4
        or HEX.fullmatch(value) is None
    ):
        raise CoverageSeedSelectionError(f"{label} must be exact lowercase hex bitmap")
    return int(value, 16)


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {
            "schema_version", "source_id", "coverage_width_bits", "baseline_hex",
            "seed_inventory_complete", "seeds",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise CoverageSeedSelectionError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    width = model["coverage_width_bits"]
    if type(width) is not int or not 8 <= width <= MAX_WIDTH_BITS or width % 8:
        raise CoverageSeedSelectionError("Coverage width must be bounded whole bytes")
    _bits(model["baseline_hex"], width, "baseline")
    core.boolean(model["seed_inventory_complete"], "seed inventory completeness")
    seen: set[str] = set()
    for item in core.bounded_list(model["seeds"], MAX_SEEDS, "seeds"):
        row = core.exact(item, {"seed_id", "coverage_hex", "cost_units"}, "seed")
        seed_id = core.identifier(row["seed_id"], "seed ID")
        if seed_id in seen:
            raise CoverageSeedSelectionError("Duplicate seed ID")
        seen.add(seed_id)
        _bits(row["coverage_hex"], width, "seed coverage")
        if type(row["cost_units"]) is not int or not 1 <= row["cost_units"] <= 10000:
            raise CoverageSeedSelectionError("Seed cost must be bounded positive units")
    return model, core.canonical(model)


def _better(candidate: tuple[int, int, str], best: tuple[int, int, str]) -> bool:
    marginal, cost, seed_id = candidate
    best_marginal, best_cost, best_id = best
    ratio_left = marginal * best_cost
    ratio_right = best_marginal * cost
    if ratio_left != ratio_right:
        return ratio_left > ratio_right
    if marginal != best_marginal:
        return marginal > best_marginal
    if cost != best_cost:
        return cost < best_cost
    return seed_id < best_id


def _derive(value: Any) -> dict:
    model, source_text = _model(value)
    width = model["coverage_width_bits"]
    baseline = _bits(model["baseline_hex"], width, "baseline")
    seeds = {
        row["seed_id"]: (
            _bits(row["coverage_hex"], width, "seed coverage"), row["cost_units"]
        )
        for row in model["seeds"]
    }
    selected: list[dict[str, int | str]] = []
    seen_bits = baseline
    remaining = set(seeds)
    while remaining:
        best: tuple[int, int, str] | None = None
        for seed_id in remaining:
            bitmap, cost = seeds[seed_id]
            candidate = ((bitmap & ~seen_bits).bit_count(), cost, seed_id)
            if candidate[0] and (best is None or _better(candidate, best)):
                best = candidate
        if best is None:
            break
        marginal, cost, seed_id = best
        seen_bits |= seeds[seed_id][0]
        selected.append({
            "seed_id": seed_id,
            "marginal_coverage_bits": marginal,
            "cost_units_asserted": cost,
            "cumulative_coverage_bits": seen_bits.bit_count(),
        })
        remaining.remove(seed_id)
    zero_gain = sorted(remaining)
    uncertainty = []
    if not model["seed_inventory_complete"]:
        uncertainty.append("supplied_seed_inventory_incomplete")
    if not seeds:
        uncertainty.append("no_seeds_supplied")
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "wave_id": WAVE_ID,
        "commander_id": COMMANDER_ID,
        "group_owner_id": GROUP_OWNER_ID,
        "independent_validator_id": INDEPENDENT_VALIDATOR_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(source_text.encode("ascii")),
        "coverage_width_bits": width,
        "baseline_coverage_bits": baseline.bit_count(),
        "final_coverage_bits": seen_bits.bit_count(),
        "seed_inventory_complete_asserted": model["seed_inventory_complete"],
        "seed_count": len(seeds),
        "selected_seeds": selected,
        "zero_gain_seed_ids": zero_gain,
        "selected_seed_count": len(selected),
        "candidate_count": 0,
        "uncertainty": uncertainty,
        "unknown_count": len(uncertainty),
        "disposition": (
            "supplied_seed_order_available" if selected and not uncertainty else "unknown"
        ),
        "source_authenticated": False,
        "coverage_instrumentation_verified": False,
        "seed_bytes_read": False,
        "target_executed": False,
        "crash_verified": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Coverage bitmaps, seed identities and costs are supplied assertions.",
            "Greedy novelty ordering is local arithmetic, not a fuzzing run.",
            "No seed bytes, target, instrumentation or crash are inspected.",
            "A selected seed is not a vulnerability or qualification candidate.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="CSS-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return report


@dataclass(frozen=True, slots=True, init=False)
class CoverageSeedSelectionReport:
    """Unsigned seed-order projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise CoverageSeedSelectionError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> CoverageSeedSelectionReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_coverage_seeds(model: Any) -> CoverageSeedSelectionReport:
    return CoverageSeedSelectionReport._owned(_derive(model))


def verify_supplied_coverage_seeds(
    report: Any, *, model: Any
) -> CoverageSeedSelectionReport:
    if type(report) is not CoverageSeedSelectionReport:
        raise CoverageSeedSelectionError("Exact seed-order wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise CoverageSeedSelectionError("Report differs from separate original model")
    return CoverageSeedSelectionReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-coverage-corpus",
        "coverage_width_bits": 8,
        "baseline_hex": "01",
        "seed_inventory_complete": True,
        "seeds": [
            {"seed_id": "seed_a", "coverage_hex": "03", "cost_units": 2},
            {"seed_id": "seed_b", "coverage_hex": "05", "cost_units": 1},
            {"seed_id": "seed_c", "coverage_hex": "80", "cost_units": 5},
            {"seed_id": "seed_d", "coverage_hex": "01", "cost_units": 1},
        ],
    }

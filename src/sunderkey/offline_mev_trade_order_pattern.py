"""Locate a supplied same-actor trade pair around a declared victim trade."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "mev_supplied_outer_trade_order_pattern"
PROFILE_ID = "AOE-GB-D10-S10"
CAPABILITY_ID = "army.gb.d10.s10"
VECTOR_ID = "AV-GB-D10-S10-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D10-S10"
WAVE_ID = "IW2-010"
COMMANDER_ID = "AOE-GB-D10-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:fa4cf53077b391bc9c5b05de72ac2371f606fead07e4333e22a11580c7c302af"
DOMAIN = "sunderkey.offline-mev-trade-order-pattern.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
DIRECTIONS = {"buy", "sell"}
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


class MevTradeOrderPatternError(ValueError):
    """A supplied ordered-trade scenario or original-model replay is invalid."""


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "scenarios"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise MevTradeOrderPatternError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    scenarios = core.bounded_list(model["scenarios"], 16, "scenarios")
    if not scenarios:
        raise MevTradeOrderPatternError("At least one scenario is required")
    seen_scenarios: set[str] = set()
    for item in scenarios:
        row = core.exact(
            item,
            {"scenario_id", "pool_id", "victim_trade_id", "context_complete", "trades"},
            "scenario",
        )
        scenario_id = core.identifier(row["scenario_id"], "scenario ID")
        if scenario_id in seen_scenarios:
            raise MevTradeOrderPatternError("Duplicate scenario ID")
        seen_scenarios.add(scenario_id)
        core.identifier(row["pool_id"], "pool ID")
        victim_trade_id = core.identifier(row["victim_trade_id"], "victim trade ID")
        core.boolean(row["context_complete"], "context completeness")
        trades = core.bounded_list(row["trades"], 32, "trades")
        if not trades:
            raise MevTradeOrderPatternError("At least one trade is required")
        seen_trades: set[str] = set()
        seen_positions: set[int] = set()
        for item_trade in trades:
            trade = core.exact(
                item_trade, {"trade_id", "actor_id", "direction", "position"}, "trade"
            )
            trade_id = core.identifier(trade["trade_id"], "trade ID")
            if trade_id in seen_trades:
                raise MevTradeOrderPatternError("Duplicate trade ID")
            seen_trades.add(trade_id)
            core.identifier(trade["actor_id"], "actor ID")
            core.choice(trade["direction"], DIRECTIONS, "trade direction")
            position = trade["position"]
            if type(position) is not int or not 0 <= position <= 1_000_000:
                raise MevTradeOrderPatternError("Trade position must be a bounded integer")
            if position in seen_positions:
                raise MevTradeOrderPatternError("Duplicate trade position")
            seen_positions.add(position)
        if victim_trade_id not in seen_trades:
            raise MevTradeOrderPatternError("Victim trade ID must identify a supplied trade")
    return model, core.canonical(model)


def _witness(row: dict) -> dict | None:
    trades = sorted(row["trades"], key=lambda trade: trade["position"])
    victim = next(trade for trade in trades if trade["trade_id"] == row["victim_trade_id"])
    opposite = "sell" if victim["direction"] == "buy" else "buy"
    for first in trades:
        if first["position"] >= victim["position"]:
            break
        if first["actor_id"] == victim["actor_id"] or first["direction"] != victim["direction"]:
            continue
        for last in trades:
            if (
                last["position"] > victim["position"]
                and last["actor_id"] == first["actor_id"]
                and last["direction"] == opposite
            ):
                return {
                    "outer_actor_id": first["actor_id"],
                    "front_trade_id": first["trade_id"],
                    "victim_trade_id": victim["trade_id"],
                    "back_trade_id": last["trade_id"],
                }
    return None


def _derive(value: Any) -> dict:
    model, model_text = _model(value)
    projections = []
    for row in model["scenarios"]:
        witness = _witness(row)
        disposition = (
            "unknown"
            if not row["context_complete"]
            else "candidate_declared_outer_trade_order_pattern"
            if witness is not None
            else "no_declared_outer_trade_order_pattern"
        )
        projections.append(
            {
                "scenario_id": row["scenario_id"],
                "pool_id": row["pool_id"],
                "trade_count": len(row["trades"]),
                "witness": witness,
                "disposition": disposition,
            }
        )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(model_text.encode("ascii")),
        "scenario_count": len(model["scenarios"]),
        "scenario_projections": projections,
        "candidate_count": sum(row["disposition"].startswith("candidate_") for row in projections),
        "unknown_count": sum(row["disposition"] == "unknown" for row in projections),
        "source_authenticated": False,
        "mempool_or_chain_queried": False,
        "economic_effect_proven": False,
        "actor_intent_proven": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Trades, actors, pools, directions and order positions are caller-supplied.",
            "The pattern omits prices, quantities, gas, liquidity, bundles and private orderflow.",
            "Ordered outer trades do not prove front-running intent, profit or harm.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="MOP-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class MevTradeOrderPatternReport:
    """Unsigned ordering projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise MevTradeOrderPatternError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> MevTradeOrderPatternReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_mev_trade_order(model: Any) -> MevTradeOrderPatternReport:
    return MevTradeOrderPatternReport._owned(_derive(model))


def verify_supplied_mev_trade_order(report: Any, *, model: Any) -> MevTradeOrderPatternReport:
    if type(report) is not MevTradeOrderPatternReport:
        raise MevTradeOrderPatternError("Exact trade-order wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise MevTradeOrderPatternError("Report differs from separate original model")
    return MevTradeOrderPatternReport._owned(expected)


def verify_supplied_mev_trade_order_bytes(
    report_bytes: bytes, *, model: Any
) -> MevTradeOrderPatternReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise MevTradeOrderPatternError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise MevTradeOrderPatternError("Exported report differs from original replay")
    return MevTradeOrderPatternReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-ordered-trades",
        "scenarios": [
            {
                "scenario_id": "scenario-one",
                "pool_id": "pool-one",
                "victim_trade_id": "victim-one",
                "context_complete": True,
                "trades": [
                    {
                        "trade_id": "front-one",
                        "actor_id": "actor-a",
                        "direction": "buy",
                        "position": 1,
                    },
                    {
                        "trade_id": "victim-one",
                        "actor_id": "actor-b",
                        "direction": "buy",
                        "position": 2,
                    },
                    {
                        "trade_id": "back-one",
                        "actor_id": "actor-a",
                        "direction": "sell",
                        "position": 3,
                    },
                ],
            }
        ],
    }

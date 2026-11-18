"""Compute supplied agent request, token, and cost-budget arithmetic."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "agent_supplied_resource_budget"
PROFILE_ID = "AOE-GD-D20-S18"
CAPABILITY_ID = "army.gd.d20.s18"
VECTOR_ID = "AV-GD-D20-S18-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D20-S18"
WAVE_ID = "IW2-020"
COMMANDER_ID = "AOE-GD-D20-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-35"
BLUEPRINT_SHA256 = "sha256:35d5d2c083781c7fc25f7d2ecb8a1f148abcbc0732f9799056bca9c890da1b73"
DOMAIN = "sunderkey.offline-agent-resource-budget.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 262_144
MAX_TOKENS_PER_EVENT = 10_000_000
MAX_RATE = 1_000_000_000
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process", "provider",
        "credentials", "target_interaction", "finding_publication", "qualification",
    )
}


class AgentResourceBudgetError(ValueError):
    """A supplied budget model or replay is invalid."""


def _integer(value: Any, label: str, maximum: int) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise AgentResourceBudgetError(f"{label} must be a bounded native integer")
    return value


def _nonempty(value: Any, label: str, maximum: int) -> list[dict]:
    rows = core.bounded_list(value, maximum, label)
    if not rows:
        raise AgentResourceBudgetError(f"{label} must not be empty")
    return rows


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "budget", "rates", "events"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise AgentResourceBudgetError("Unsupported model version")
    core.identifier(model["source_id"], "model source ID")
    budget = core.exact(
        model["budget"],
        {"maximum_requests", "maximum_tokens", "maximum_cost_micro_usd"},
        "budget",
    )
    _integer(budget["maximum_requests"], "request ceiling", 128)
    _integer(budget["maximum_tokens"], "token ceiling", 2_560_000_000)
    _integer(budget["maximum_cost_micro_usd"], "cost ceiling", 2_560_000_000_000)
    rates: set[str] = set()
    for item in _nonempty(model["rates"], "rates", 32):
        row = core.exact(
            item,
            {"model_id", "input_micro_usd_per_million", "output_micro_usd_per_million"},
            "rate",
        )
        model_id = core.identifier(row["model_id"], "rate model ID")
        if model_id in rates:
            raise AgentResourceBudgetError("Duplicate rate model ID")
        rates.add(model_id)
        _integer(row["input_micro_usd_per_million"], "input rate", MAX_RATE)
        _integer(row["output_micro_usd_per_million"], "output rate", MAX_RATE)
    events: set[str] = set()
    for item in _nonempty(model["events"], "events", 128):
        row = core.exact(
            item,
            {
                "request_id", "model_id", "input_tokens", "output_tokens",
                "admission", "context_complete",
            },
            "event",
        )
        request_id = core.identifier(row["request_id"], "request ID")
        if request_id in events:
            raise AgentResourceBudgetError("Duplicate request ID")
        events.add(request_id)
        model_id = core.identifier(row["model_id"], "event model ID")
        if model_id not in rates:
            raise AgentResourceBudgetError("Event references an absent rate")
        _integer(row["input_tokens"], "input tokens", MAX_TOKENS_PER_EVENT)
        _integer(row["output_tokens"], "output tokens", MAX_TOKENS_PER_EVENT)
        core.choice(row["admission"], {"accepted", "rejected", "unknown"}, "admission")
        core.boolean(row["context_complete"], "context completeness")
    return model, core.canonical(model)


def _cost(event: dict, rate: dict) -> int:
    numerator = (
        event["input_tokens"] * rate["input_micro_usd_per_million"]
        + event["output_tokens"] * rate["output_micro_usd_per_million"]
    )
    return (numerator + 999_999) // 1_000_000


def _derive(value: Any) -> dict:
    model, model_text = _model(value)
    budget = model["budget"]
    rates = {row["model_id"]: row for row in model["rates"]}
    requests = tokens = cost = 0
    complete = True
    projections = []
    for item in model["events"]:
        if not item["context_complete"] or item["admission"] == "unknown":
            complete = False
        if not complete:
            projections.append({
                "request_id": item["request_id"],
                "disposition": "unknown",
                "cumulative_requests": None,
                "cumulative_tokens": None,
                "cumulative_cost_micro_usd": None,
            })
            continue
        if item["admission"] == "rejected":
            disposition = "declared_rejected"
        else:
            requests += 1
            tokens += item["input_tokens"] + item["output_tokens"]
            cost += _cost(item, rates[item["model_id"]])
            exceeded = (
                requests > budget["maximum_requests"]
                or tokens > budget["maximum_tokens"]
                or cost > budget["maximum_cost_micro_usd"]
            )
            disposition = (
                "candidate_declared_budget_exceeded" if exceeded
                else "within_declared_budget"
            )
        projections.append({
            "request_id": item["request_id"],
            "disposition": disposition,
            "cumulative_requests": requests,
            "cumulative_tokens": tokens,
            "cumulative_cost_micro_usd": cost,
        })
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model": model,
        "source_model_sha256": core.digest(model_text.encode("ascii")),
        "event_projections": projections,
        "candidate_count": sum(
            item["disposition"] == "candidate_declared_budget_exceeded"
            for item in projections
        ),
        "unknown_count": sum(item["disposition"] == "unknown" for item in projections),
        "source_authenticated": False,
        "provider_billing_verified": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Rates, tokens, ordering, admissions and ceilings are supplied declarations.",
            "Micro-USD cost uses per-request upward integer rounding, not provider billing.",
            "An unknown event makes later cumulative totals unknown; no provider is called.",
            "A candidate is declared arithmetic over budget, not observed abuse.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="ARB-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class AgentResourceBudgetReport:
    """Unsigned projection requiring separately retained original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise AgentResourceBudgetError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> AgentResourceBudgetReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_agent_resource_budget(model: Any) -> AgentResourceBudgetReport:
    return AgentResourceBudgetReport._owned(_derive(model))


def verify_supplied_agent_resource_budget(
    report: Any, *, model: Any
) -> AgentResourceBudgetReport:
    if type(report) is not AgentResourceBudgetReport:
        raise AgentResourceBudgetError("Exact resource-budget wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise AgentResourceBudgetError("Report differs from separate original model")
    return AgentResourceBudgetReport._owned(expected)


def verify_supplied_agent_resource_budget_bytes(
    report_bytes: bytes, *, model: Any
) -> AgentResourceBudgetReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise AgentResourceBudgetError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise AgentResourceBudgetError("Exported report differs from original replay")
    return AgentResourceBudgetReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-agent-budget",
        "budget": {
            "maximum_requests": 2,
            "maximum_tokens": 5,
            "maximum_cost_micro_usd": 5,
        },
        "rates": [
            {
                "model_id": "model-one",
                "input_micro_usd_per_million": 1_000_000,
                "output_micro_usd_per_million": 2_000_000,
            },
        ],
        "events": [
            {
                "request_id": "first", "model_id": "model-one",
                "input_tokens": 1, "output_tokens": 1,
                "admission": "accepted", "context_complete": True,
            },
            {
                "request_id": "second", "model_id": "model-one",
                "input_tokens": 1, "output_tokens": 1,
                "admission": "accepted", "context_complete": True,
            },
            {
                "request_id": "rejected", "model_id": "model-one",
                "input_tokens": 1, "output_tokens": 1,
                "admission": "rejected", "context_complete": True,
            },
            {
                "request_id": "unknown", "model_id": "model-one",
                "input_tokens": 1, "output_tokens": 1,
                "admission": "unknown", "context_complete": True,
            },
            {
                "request_id": "after-unknown", "model_id": "model-one",
                "input_tokens": 1, "output_tokens": 1,
                "admission": "accepted", "context_complete": True,
            },
        ],
    }

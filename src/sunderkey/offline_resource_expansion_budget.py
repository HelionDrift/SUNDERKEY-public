"""Compare supplied finite expansion arithmetic with a declared work budget."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "supplied_resource_expansion_budget"
PROFILE_ID = "AOE-GE-D23-S11"
CAPABILITY_ID = "army.ge.d23.s11"
VECTOR_ID = "AV-GE-D23-S11-01"
WORK_PACKAGE_ID = "IWP2-AOE-GE-D23-S11"
WAVE_ID = "IW2-025"
COMMANDER_ID = "AOE-GE-D23-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:f40bcd72f51050940a567ebe5c2f7a9f5321928f33d9d6fc3a979317f6c4636d"
SEMANTICS_PROFILE = "supplied-finite-expansion-budget-v1"
DOMAIN = "sunderkey.offline-resource-expansion-budget.v1"
MAX_DOCUMENT_BYTES = 65_536
MAX_OPERATIONS = 128
MAX_NATIVE_NODES = 2_048
MAX_NATIVE_DEPTH = 10
WORK_SATURATION = 1_000_000_001
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_OUTCOMES = frozenset({"accepted", "rejected", "unknown"})
_EFFECTS = dict.fromkeys(
    (
        "authority", "credential", "execution", "filesystem", "network",
        "publication", "qualification", "target",
    ),
    "none",
)


class ResourceExpansionBudgetError(ValueError):
    """A supplied expansion model or replay report was refused."""


def _canonical(value: Any) -> str:
    nodes = 0
    active: set[int] = set()

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_NATIVE_NODES or depth > MAX_NATIVE_DEPTH:
            raise ResourceExpansionBudgetError("Native structure bound exceeded")
        family = type(item)
        if family is str:
            if len(item) > MAX_DOCUMENT_BYTES:
                raise ResourceExpansionBudgetError("Native string bound exceeded")
            return
        if family is bool or item is None:
            return
        if family is int:
            if not 0 <= item <= WORK_SATURATION:
                raise ResourceExpansionBudgetError("Native integer bound exceeded")
            return
        if family not in (dict, list):
            raise ResourceExpansionBudgetError("Only exact native JSON values are accepted")
        if id(item) in active:
            raise ResourceExpansionBudgetError("Cyclic native document refused")
        active.add(id(item))
        try:
            if family is dict:
                for key, child in item.items():
                    if type(key) is not str:
                        raise ResourceExpansionBudgetError("Native JSON text keys are required")
                    visit(key, depth + 1)
                    visit(child, depth + 1)
            else:
                for child in item:
                    visit(child, depth + 1)
        finally:
            active.remove(id(item))

    visit(value, 1)
    encoded = json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    )
    if len(encoded) > MAX_DOCUMENT_BYTES:
        raise ResourceExpansionBudgetError("Document byte bound exceeded")
    return encoded


def _fields(value: Any, names: set[str], label: str) -> None:
    if type(value) is not dict or value.keys() != names:
        raise ResourceExpansionBudgetError(f"{label} fields are invalid")


def _integer(value: Any, minimum: int, maximum: int, label: str) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ResourceExpansionBudgetError(f"{label} is outside the finite range")
    return value


def _model(value: Any) -> dict:
    model = json.loads(_canonical(value))
    _fields(
        model,
        {"schema_version", "semantics_profile", "source_id", "policy", "operations"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise ResourceExpansionBudgetError("Schema version is invalid")
    if model["semantics_profile"] != SEMANTICS_PROFILE:
        raise ResourceExpansionBudgetError("Semantics profile is invalid")
    if type(model["source_id"]) is not str or _ID.fullmatch(model["source_id"]) is None:
        raise ResourceExpansionBudgetError("Source identifier is invalid")
    policy = model["policy"]
    _fields(
        policy,
        {"declaration_complete", "reject_over_capacity", "capacity_units"},
        "policy",
    )
    for field in ("declaration_complete", "reject_over_capacity"):
        if type(policy[field]) is not bool:
            raise ResourceExpansionBudgetError(f"{field} must be boolean")
    _integer(policy["capacity_units"], 1, 1_000_000_000, "Capacity")
    operations = model["operations"]
    if type(operations) is not list or not 1 <= len(operations) <= MAX_OPERATIONS:
        raise ResourceExpansionBudgetError("Operation count is invalid")
    identifiers: set[str] = set()
    for item in operations:
        _fields(
            item,
            {
                "operation_id", "input_units", "fanout", "depth",
                "capture_complete", "declared_outcome",
            },
            "operation",
        )
        identity = item["operation_id"]
        if type(identity) is not str or _ID.fullmatch(identity) is None:
            raise ResourceExpansionBudgetError("Operation identifier is invalid")
        if identity in identifiers:
            raise ResourceExpansionBudgetError("Operation identifier is repeated")
        identifiers.add(identity)
        _integer(item["input_units"], 1, 1_000_000, "Input units")
        _integer(item["fanout"], 1, 32, "Fanout")
        _integer(item["depth"], 0, 32, "Depth")
        if type(item["capture_complete"]) is not bool:
            raise ResourceExpansionBudgetError("Capture-complete declaration must be boolean")
        if type(item["declared_outcome"]) is not str or item["declared_outcome"] not in _OUTCOMES:
            raise ResourceExpansionBudgetError("Declared outcome is invalid")
    return model


def _work(input_units: int, fanout: int, depth: int) -> tuple[int, bool]:
    level = input_units
    total = 0
    for _ in range(depth + 1):
        total += level
        if total > WORK_SATURATION:
            return WORK_SATURATION, True
        level = min(level * fanout, WORK_SATURATION + 1)
    return total, False


def _derive(value: Any) -> dict:
    model = _model(value)
    policy = model["policy"]
    projections = []
    for item in sorted(model["operations"], key=lambda row: row["operation_id"]):
        projected, saturated = _work(
            item["input_units"], item["fanout"], item["depth"]
        )
        over = projected > policy["capacity_units"]
        negative = policy["reject_over_capacity"] and over
        if not policy["declaration_complete"] or not item["capture_complete"]:
            disposition = "unresolved_declaration_or_capture"
        elif item["declared_outcome"] == "unknown":
            disposition = "unresolved_outcome"
        elif not negative:
            disposition = "no_declared_negative_invariant"
        elif item["declared_outcome"] == "accepted":
            disposition = "candidate_declared_resource_budget_conflict"
        else:
            disposition = "declared_reject_consistent"
        projections.append(
            {
                "operation_id": item["operation_id"],
                "projected_work_units": projected,
                "projection_saturated": saturated,
                "declared_capacity_units": policy["capacity_units"],
                "negative_predicate": "declared_capacity_exceeded" if negative else None,
                "disposition": disposition,
            }
        )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "source_model": model,
        "operation_count": len(projections),
        "projections": projections,
        "flags": {
            "work_units_measured": False,
            "target_capacity_verified": False,
            "resource_exhaustion_verified": False,
            "workload_generated": False,
            "positive_use_approved": False,
            "qualification_claimed": False,
        },
        "operational_effects": dict(_EFFECTS),
        "limitations": [
            "Expansion factors, capacity policy and outcomes are caller assertions.",
            "The arithmetic projection is not measured target resource use.",
            "Saturated work is a comparison bound, not an exact work count.",
            "A declared conflict does not prove resource exhaustion or availability impact.",
            "No workload, file, credential, network, process or target is accessed.",
        ],
    }
    digest = "sha256:" + hashlib.sha256(
        (DOMAIN + "\n" + _canonical(body)).encode("ascii")
    ).hexdigest()
    return json.loads(_canonical({
        **body, "analysis_id": "REB-" + digest[7:39].upper(), "analysis_sha256": digest
    }))


@dataclass(frozen=True, slots=True, init=False)
class ResourceExpansionBudget:
    """Immutable report replayed from a supplied finite expansion model."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        if type(document) is not dict or type(document.get("source_model")) is not dict:
            raise ResourceExpansionBudgetError("Exact native report with source model required")
        expected = _derive(document["source_model"])
        if _canonical(document) != _canonical(expected):
            raise ResourceExpansionBudgetError("Report differs from embedded source replay")
        object.__setattr__(self, "_document_json", _canonical(expected))

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_resource_expansion_budget(model: Any) -> ResourceExpansionBudget:
    """Compare a supplied expansion budget without generating workload."""
    return ResourceExpansionBudget(_derive(model))


def verify_supplied_resource_expansion_budget(
    report: Any, *, model: Any
) -> ResourceExpansionBudget:
    if type(report) is not ResourceExpansionBudget:
        raise ResourceExpansionBudgetError("Exact native analysis wrapper required")
    expected = _derive(model)
    if report.to_json() != _canonical(expected):
        raise ResourceExpansionBudgetError("Report differs from supplied source replay")
    return ResourceExpansionBudget(expected)

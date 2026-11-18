"""Replay supplied minor-unit price and tax-rounding arithmetic offline."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "supplied_price_rounding_arithmetic"
PROFILE_ID = "AOE-GB-D09-S02"
CAPABILITY_ID = "army.gb.d09.s02"
VECTOR_ID = "AV-GB-D09-S02-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D09-S02"
WAVE_ID = "IW2-002"
COMMANDER_ID = "AOE-GB-D09-CMD"
GROUP_OWNER_ID = "AOE-HQ-04"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:a3270b3386555768dd1963a06cadaa9c7d5cb0cca3d81417450e9c9d27a4f35d"
SEMANTICS_PROFILE = "supplied-minor-unit-price-rounding-v1"
DOMAIN = "sunderkey.offline-price-rounding-analysis.v1"
MAX_LINES = 128
MAX_UNIT_MINOR = 1_000_000_000
MAX_QUANTITY = 100_000
MAX_AMOUNT = 10_000_000_000_000_000
MAX_DOCUMENT_BYTES = 262_144
MAX_NATIVE_NODES = 16_384
MAX_NATIVE_DEPTH = 12
MAX_STRING_LENGTH = 256
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_CURRENCY = re.compile(r"[A-Z]{3}\Z")
_EFFECTS = dict.fromkeys(
    (
        "authority",
        "credential",
        "execution",
        "financial_transaction",
        "filesystem",
        "network",
        "payment",
        "publication",
        "qualification",
        "target",
    ),
    "none",
)


class PriceRoundingAnalysisError(ValueError):
    """The supplied arithmetic model or replay document was refused."""


def _fields(value: Any, names: set[str], label: str) -> None:
    if type(value) is not dict or value.keys() != names:
        raise PriceRoundingAnalysisError(f"{label} fields are invalid")


def _amount(value: Any, label: str, *, maximum: int = MAX_AMOUNT) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise PriceRoundingAnalysisError(f"{label} amount is invalid")
    return value


def _canonical(value: Any) -> str:
    nodes = 0
    active: set[int] = set()

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_NATIVE_NODES or depth > MAX_NATIVE_DEPTH:
            raise PriceRoundingAnalysisError("Native document structure bound exceeded")
        family = type(item)
        if family is str:
            if len(item) > MAX_STRING_LENGTH:
                raise PriceRoundingAnalysisError("Native document string bound exceeded")
            return
        if family is bool or item is None:
            return
        if family is int:
            if not -(1 << 63) <= item < (1 << 63):
                raise PriceRoundingAnalysisError("Native document integer bound exceeded")
            return
        if family not in (dict, list):
            raise PriceRoundingAnalysisError("Only exact native JSON values are accepted")
        if id(item) in active:
            raise PriceRoundingAnalysisError("Cyclic native document refused")
        active.add(id(item))
        try:
            if family is dict:
                for key, child in item.items():
                    if type(key) is not str:
                        raise PriceRoundingAnalysisError("Native JSON text keys are required")
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
        raise PriceRoundingAnalysisError("Document byte bound exceeded")
    return encoded


def _plan(model: Any) -> dict:
    model = json.loads(_canonical(model))
    _fields(
        model,
        {
            "schema_version",
            "semantics_profile",
            "currency_label",
            "minor_unit_scale",
            "lines",
            "tax_rate_basis_points",
            "tax_basis",
            "rounding_mode",
            "declared_subtotal_minor",
            "declared_discount_minor",
            "declared_tax_minor",
            "declared_total_minor",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise PriceRoundingAnalysisError("Schema version is invalid")
    if model["semantics_profile"] != SEMANTICS_PROFILE:
        raise PriceRoundingAnalysisError("Semantics profile is invalid")
    if (
        type(model["currency_label"]) is not str
        or _CURRENCY.fullmatch(model["currency_label"]) is None
    ):
        raise PriceRoundingAnalysisError("Currency label is invalid")
    if type(model["minor_unit_scale"]) is not int or not 0 <= model["minor_unit_scale"] <= 4:
        raise PriceRoundingAnalysisError("Minor-unit scale is invalid")
    if model["tax_basis"] not in ("line", "order"):
        raise PriceRoundingAnalysisError("Tax basis is invalid")
    if model["rounding_mode"] not in ("floor", "half_up"):
        raise PriceRoundingAnalysisError("Rounding mode is invalid")
    _amount(model["tax_rate_basis_points"], "tax rate", maximum=10_000)
    for field in (
        "declared_subtotal_minor",
        "declared_discount_minor",
        "declared_tax_minor",
        "declared_total_minor",
    ):
        _amount(model[field], field)
    lines = model["lines"]
    if type(lines) is not list or not 1 <= len(lines) <= MAX_LINES:
        raise PriceRoundingAnalysisError("Line count is invalid")
    ids: set[str] = set()
    for line in lines:
        _fields(line, {"line_id", "unit_minor", "quantity", "discount_minor"}, "line")
        if type(line["line_id"]) is not str or _ID.fullmatch(line["line_id"]) is None:
            raise PriceRoundingAnalysisError("Line identifier is invalid")
        if line["line_id"] in ids:
            raise PriceRoundingAnalysisError("Duplicate line identifier")
        ids.add(line["line_id"])
        unit = _amount(line["unit_minor"], "unit", maximum=MAX_UNIT_MINOR)
        quantity = _amount(line["quantity"], "quantity", maximum=MAX_QUANTITY)
        if quantity == 0:
            raise PriceRoundingAnalysisError("Quantity must be positive")
        gross = unit * quantity
        discount = _amount(line["discount_minor"], "discount")
        if gross > MAX_AMOUNT or discount > gross:
            raise PriceRoundingAnalysisError("Line gross or discount exceeds bound")
    return model


def _rounded_tax(net_minor: int, basis_points: int, mode: str) -> int:
    whole, remainder = divmod(net_minor * basis_points, 10_000)
    return whole + int(mode == "half_up" and remainder * 2 >= 10_000)


def _derive(model: Any) -> dict:
    plan = _plan(model)
    rate = plan["tax_rate_basis_points"]
    mode = plan["rounding_mode"]
    subtotal = 0
    discount = 0
    line_tax = 0
    line_results = []
    for line in sorted(plan["lines"], key=lambda row: row["line_id"]):
        gross = line["unit_minor"] * line["quantity"]
        net = gross - line["discount_minor"]
        tax = _rounded_tax(net, rate, mode)
        subtotal += gross
        discount += line["discount_minor"]
        line_tax += tax
        line_results.append(
            {
                "line_id": line["line_id"],
                "gross_minor": gross,
                "net_minor": net,
                "rounded_line_tax_minor": tax,
            }
        )
    net_total = subtotal - discount
    order_tax = _rounded_tax(net_total, rate, mode)
    selected_tax = line_tax if plan["tax_basis"] == "line" else order_tax
    expected_total = net_total + selected_tax
    if max(subtotal, discount, line_tax, order_tax, expected_total) > MAX_AMOUNT:
        raise PriceRoundingAnalysisError("Aggregate arithmetic exceeds hard bound")
    expected = {
        "subtotal_minor": subtotal,
        "discount_minor": discount,
        "line_tax_minor": line_tax,
        "order_tax_minor": order_tax,
        "selected_tax_minor": selected_tax,
        "total_minor": expected_total,
        "line_order_rounding_gap_minor": line_tax - order_tax,
    }
    comparison = {
        "subtotal": "match" if plan["declared_subtotal_minor"] == subtotal else "mismatch",
        "discount": "match" if plan["declared_discount_minor"] == discount else "mismatch",
        "tax": "match" if plan["declared_tax_minor"] == selected_tax else "mismatch",
        "total": "match" if plan["declared_total_minor"] == expected_total else "mismatch",
    }
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "source_model": plan,
        "line_results": line_results,
        "expected": expected,
        "comparison": comparison,
        "flags": {
            "currency_registry_validated": False,
            "product_rules_authenticated": False,
            "tax_policy_proven": False,
            "payment_executed": False,
            "economic_impact_proven": False,
            "positive_use_approved": False,
            "qualification_claimed": False,
        },
        "operational_effects": dict(_EFFECTS),
        "limitations": [
            "Currency label, scale, tax basis, rate and rounding policy are caller-supplied.",
            "Only integer minor-unit arithmetic is modeled; no FX or real tax law is checked.",
            "A supplied mismatch is not proof of deployed behavior or economic loss.",
            "No checkout, payment, target interaction or financial transaction runs.",
        ],
    }
    digest = (
        "sha256:" + hashlib.sha256((DOMAIN + "\n" + _canonical(body)).encode("ascii")).hexdigest()
    )
    return json.loads(
        _canonical(
            {**body, "analysis_id": "PRA-" + digest[7:39].upper(), "analysis_sha256": digest}
        )
    )


@dataclass(frozen=True, slots=True, init=False)
class PriceRoundingAnalysis:
    """Replay-checked supplied arithmetic without monetary or target effect."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        if type(document) is not dict or type(document.get("source_model")) is not dict:
            raise PriceRoundingAnalysisError("Exact native report with source model required")
        expected = _derive(document["source_model"])
        if _canonical(document) != _canonical(expected):
            raise PriceRoundingAnalysisError("Report differs from embedded model replay")
        object.__setattr__(self, "_document_json", _canonical(expected))

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_price_rounding(model: Any) -> PriceRoundingAnalysis:
    """Compare declared prices with bounded integer arithmetic only."""
    return PriceRoundingAnalysis(_derive(model))


def verify_supplied_price_rounding(report: Any, *, model: Any) -> PriceRoundingAnalysis:
    """Independently rederive expected arithmetic from current supplied input."""
    if type(report) is not PriceRoundingAnalysis:
        raise PriceRoundingAnalysisError("Exact native analysis wrapper required")
    expected = _derive(model)
    if report.to_json() != _canonical(expected):
        raise PriceRoundingAnalysisError("Report differs from supplied model replay")
    return PriceRoundingAnalysis(expected)


__all__ = [
    "COMPONENT_ID",
    "PROFILE_ID",
    "PriceRoundingAnalysis",
    "PriceRoundingAnalysisError",
    "analyze_supplied_price_rounding",
    "verify_supplied_price_rounding",
]

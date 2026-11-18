"""Check supplied fixed-width arithmetic without executing a program."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "exploit_supplied_integer_width_arithmetic"
PROFILE_ID = "AOE-GE-D21-S12"
CAPABILITY_ID = "army.ge.d21.s12"
VECTOR_ID = "AV-GE-D21-S12-01"
WORK_PACKAGE_ID = "IWP2-AOE-GE-D21-S12"
WAVE_ID = "IW2-024"
COMMANDER_ID = "AOE-GE-D21-CMD"
GROUP_OWNER_ID = "AOE-HQ-07"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:7e76db2e086877960d742356e7c16ca0bdad36329a25cbb19dd060e950db128e"
DOMAIN = "sunderkey.offline-integer-width-arithmetic.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
MAX_OPERATIONS = 32
WIDTHS = frozenset({8, 16, 32, 64})
OPERATORS = frozenset({"add", "subtract", "multiply"})
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process",
        "provider", "credentials", "target_interaction",
        "finding_publication", "qualification",
    )
}


class IntegerWidthArithmeticError(ValueError):
    """The supplied arithmetic model or original-model replay is invalid."""


def _bounds(width: int, signed: bool) -> tuple[int, int]:
    if signed:
        return -(1 << (width - 1)), (1 << (width - 1)) - 1
    return 0, (1 << width) - 1


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "operation_inventory_complete", "operations"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise IntegerWidthArithmeticError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["operation_inventory_complete"], "inventory completeness")
    rows = core.bounded_list(model["operations"], MAX_OPERATIONS, "operations")
    if not rows:
        raise IntegerWidthArithmeticError("At least one operation is required")
    seen = set()
    for item in rows:
        row = core.exact(
            item,
            {"operation_id", "width_bits", "signed", "operator", "left", "right",
             "observed_result"},
            "operation",
        )
        operation_id = core.identifier(row["operation_id"], "operation ID")
        if operation_id in seen:
            raise IntegerWidthArithmeticError("Duplicate operation ID")
        seen.add(operation_id)
        width = row["width_bits"]
        if type(width) is not int or width not in WIDTHS:
            raise IntegerWidthArithmeticError("Unsupported integer width")
        core.boolean(row["signed"], "signed flag")
        if width == 64 and not row["signed"]:
            raise IntegerWidthArithmeticError("Unsigned 64-bit values exceed JSON integer boundary")
        core.choice(row["operator"], set(OPERATORS), "operator")
        lower, upper = _bounds(width, row["signed"])
        for field in ("left", "right", "observed_result"):
            number = row[field]
            if field == "observed_result" and number is None:
                continue
            if type(number) is not int or not lower <= number <= upper:
                raise IntegerWidthArithmeticError(f"{field} is outside declared width")
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, source_text = _model(value)
    results = []
    for row in sorted(model["operations"], key=lambda item: item["operation_id"]):
        left, right = row["left"], row["right"]
        operator = row["operator"]
        if operator == "add":
            arithmetic = left + right
        elif operator == "subtract":
            arithmetic = left - right
        else:
            arithmetic = left * right
        width, signed = row["width_bits"], row["signed"]
        lower, upper = _bounds(width, signed)
        residue = arithmetic % (1 << width)
        wrapped = (
            residue - (1 << width)
            if signed and residue >= (1 << (width - 1))
            else residue
        )
        observed = row["observed_result"]
        results.append({
            "operation_id": row["operation_id"],
            "width_bits": width,
            "signed": signed,
            "operator": operator,
            "mathematical_result_decimal": str(arithmetic),
            "wrapped_result": wrapped,
            "declared_width_overflow": arithmetic < lower or arithmetic > upper,
            "supplied_observed_result": observed,
            "observed_matches_wrapped": None if observed is None else observed == wrapped,
        })
    uncertainty = []
    if not model["operation_inventory_complete"]:
        uncertainty.append("supplied_operation_inventory_incomplete")
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
        "operation_inventory_complete_asserted": model["operation_inventory_complete"],
        "operation_count": len(results),
        "overflow_operation_count": sum(row["declared_width_overflow"] for row in results),
        "observed_mismatch_count": sum(
            row["observed_matches_wrapped"] is False for row in results
        ),
        "results": results,
        "candidate_count": 0,
        "uncertainty": uncertainty,
        "unknown_count": len(uncertainty),
        "disposition": "unknown" if uncertainty else "supplied_width_arithmetic_projection",
        "source_authenticated": False,
        "program_operations_verified": False,
        "observations_verified": False,
        "target_executed": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Widths, signs, operations, operands and observations are supplied assertions.",
            "Mathematical wraparound is not proof of a program flaw or exploitability.",
            "Language-specific undefined behavior and compiler behavior are not modeled.",
            "No program, process, target, or vulnerability test is run.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="IWA-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return report


@dataclass(frozen=True, slots=True, init=False)
class IntegerWidthArithmeticReport:
    """Unsigned arithmetic projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise IntegerWidthArithmeticError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> IntegerWidthArithmeticReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_integer_width(model: Any) -> IntegerWidthArithmeticReport:
    return IntegerWidthArithmeticReport._owned(_derive(model))


def verify_supplied_integer_width(
    report: Any, *, model: Any
) -> IntegerWidthArithmeticReport:
    if type(report) is not IntegerWidthArithmeticReport:
        raise IntegerWidthArithmeticError("Exact arithmetic wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise IntegerWidthArithmeticError("Report differs from separate original model")
    return IntegerWidthArithmeticReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-width-arithmetic",
        "operation_inventory_complete": True,
        "operations": [
            {
                "operation_id": "unsigned_add", "width_bits": 8, "signed": False,
                "operator": "add", "left": 250, "right": 10, "observed_result": 4,
            },
            {
                "operation_id": "signed_multiply", "width_bits": 8, "signed": True,
                "operator": "multiply", "left": 20, "right": 10, "observed_result": -56,
            },
        ],
    }

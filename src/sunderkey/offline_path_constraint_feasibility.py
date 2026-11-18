"""Enumerate a small supplied linear path-condition model without target use."""

from __future__ import annotations

import itertools
import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "exploit_supplied_path_constraint_feasibility"
PROFILE_ID = "AOE-GE-D21-S15"
CAPABILITY_ID = "army.ge.d21.s15"
VECTOR_ID = "AV-GE-D21-S15-01"
WORK_PACKAGE_ID = "IWP2-AOE-GE-D21-S15"
WAVE_ID = "IW2-027"
COMMANDER_ID = "AOE-GE-D21-CMD"
GROUP_OWNER_ID = "AOE-HQ-07"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:64fedad60aab560825eee58c67654c9583d8e0140583172ae95e685af1628b18"
DOMAIN = "sunderkey.offline-path-constraint-feasibility.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
MAX_VARIABLES = 4
MAX_DOMAIN_VALUES = 16
MAX_CONSTRAINTS = 16
MAX_ASSIGNMENTS = 65_536
OPERATORS = frozenset({"eq", "ne", "lt", "le", "gt", "ge"})
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process",
        "provider", "credentials", "target_interaction",
        "finding_publication", "qualification",
    )
}


class PathConstraintFeasibilityError(ValueError):
    """The supplied path model or original-model replay is invalid."""


def _bounded_int(value: Any, label: str, limit: int = 1000) -> int:
    if type(value) is not int or not -limit <= value <= limit:
        raise PathConstraintFeasibilityError(f"{label} must be bounded native integer")
    return value


def _model(value: Any) -> tuple[dict, list[tuple[str, list[int]]], str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "path_conditions_complete", "variables", "constraints"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise PathConstraintFeasibilityError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["path_conditions_complete"], "path completeness")
    variables = []
    seen: set[str] = set()
    assignment_count = 1
    for item in core.bounded_list(model["variables"], MAX_VARIABLES, "variables"):
        row = core.exact(item, {"name", "domain"}, "variable")
        name = core.identifier(row["name"], "variable name")
        if name in seen:
            raise PathConstraintFeasibilityError("Duplicate variable")
        seen.add(name)
        domain = [
            _bounded_int(number, "domain value")
            for number in core.bounded_list(row["domain"], MAX_DOMAIN_VALUES, "domain")
        ]
        if not domain or domain != sorted(set(domain)):
            raise PathConstraintFeasibilityError("Domain must be nonempty sorted unique integers")
        assignment_count *= len(domain)
        if assignment_count > MAX_ASSIGNMENTS:
            raise PathConstraintFeasibilityError("Assignment limit exceeded")
        variables.append((name, domain))
    if not variables:
        raise PathConstraintFeasibilityError("At least one variable is required")
    variables.sort(key=lambda item: item[0])
    constraints = core.bounded_list(model["constraints"], MAX_CONSTRAINTS, "constraints")
    if not constraints:
        raise PathConstraintFeasibilityError("At least one condition is required")
    for item in constraints:
        row = core.exact(item, {"coefficients", "constant", "operator"}, "condition")
        if type(row["coefficients"]) is not dict or not row["coefficients"]:
            raise PathConstraintFeasibilityError("Condition needs coefficients")
        if not set(row["coefficients"]).issubset(seen):
            raise PathConstraintFeasibilityError("Condition references unknown variable")
        for coefficient in row["coefficients"].values():
            if not _bounded_int(coefficient, "coefficient"):
                raise PathConstraintFeasibilityError("Zero coefficient is not permitted")
        _bounded_int(row["constant"], "constant")
        core.choice(row["operator"], set(OPERATORS), "operator")
    return model, variables, core.canonical(model)


def _satisfied(condition: dict, assignment: dict[str, int]) -> bool:
    value = condition["constant"] + sum(
        coefficient * assignment[name]
        for name, coefficient in condition["coefficients"].items()
    )
    operator = condition["operator"]
    return {
        "eq": value == 0,
        "ne": value != 0,
        "lt": value < 0,
        "le": value <= 0,
        "gt": value > 0,
        "ge": value >= 0,
    }[operator]


def _derive(value: Any) -> dict:
    model, variables, source_text = _model(value)
    names = [name for name, _ in variables]
    total = 1
    for _, domain in variables:
        total *= len(domain)
    satisfying = 0
    first_witness: dict[str, int] | None = None
    for values in itertools.product(*(domain for _, domain in variables)):
        assignment = dict(zip(names, values, strict=True))
        if all(_satisfied(condition, assignment) for condition in model["constraints"]):
            satisfying += 1
            if first_witness is None:
                first_witness = assignment
    uncertainty = []
    if not model["path_conditions_complete"]:
        uncertainty.append("supplied_conditions_incomplete")
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
        "path_conditions_complete_asserted": model["path_conditions_complete"],
        "variable_count": len(variables),
        "condition_count": len(model["constraints"]),
        "enumerated_assignment_count": total,
        "satisfying_assignment_count": satisfying,
        "first_supplied_model_witness": first_witness,
        "candidate_count": 0,
        "uncertainty": uncertainty,
        "unknown_count": len(uncertainty),
        "disposition": "unknown" if uncertainty else (
            "supplied_model_satisfiable" if satisfying else "supplied_model_unsatisfiable"
        ),
        "source_authenticated": False,
        "constraints_extracted_from_program": False,
        "path_reachable_in_target": False,
        "program_executed": False,
        "target_executed": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Variables, domains, linear conditions and completeness are supplied assertions.",
            "Enumeration proves only satisfiability inside the finite supplied model.",
            "No program trace, symbolic executor, solver, or target is invoked.",
            "A satisfying assignment is not a reachable exploit or finding.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="PCF-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return report


@dataclass(frozen=True, slots=True, init=False)
class PathConstraintFeasibilityReport:
    """Unsigned finite-model result requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise PathConstraintFeasibilityError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> PathConstraintFeasibilityReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_path_constraints(model: Any) -> PathConstraintFeasibilityReport:
    return PathConstraintFeasibilityReport._owned(_derive(model))


def verify_supplied_path_constraints(
    report: Any, *, model: Any
) -> PathConstraintFeasibilityReport:
    if type(report) is not PathConstraintFeasibilityReport:
        raise PathConstraintFeasibilityError("Exact constraint wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise PathConstraintFeasibilityError("Report differs from separate original model")
    return PathConstraintFeasibilityReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-path-conditions",
        "path_conditions_complete": True,
        "variables": [
            {"name": "x", "domain": [0, 1, 2, 3]},
            {"name": "y", "domain": [0, 1]},
        ],
        "constraints": [
            {"coefficients": {"x": 1, "y": 1}, "constant": -3, "operator": "eq"},
            {"coefficients": {"x": 1}, "constant": -2, "operator": "ge"},
        ],
    }

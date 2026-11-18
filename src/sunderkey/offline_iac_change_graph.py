"""Project supplied, value-free Infrastructure-as-Code change dependencies."""

from __future__ import annotations

import json
import re
from collections import deque
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "iac_supplied_change_dependency_projection"
PROFILE_ID = "AOE-GC-D17-S12"
CAPABILITY_ID = "army.gc.d17.s12"
VECTOR_ID = "AV-GC-D17-S12-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D17-S12"
WAVE_ID = "IW2-024"
COMMANDER_ID = "AOE-GC-D17-CMD"
GROUP_OWNER_ID = "AOE-HQ-05"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:4aaa3dc25dd5a21207d8436c5b78e4a7746ef2d84933b442ba92ab13c63401f5"
DOMAIN = "sunderkey.offline-iac-change-graph.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
MAX_RESOURCES = 128
MAX_DEPENDENCIES = 32
MAX_PROTECTED = 64
_ADDRESS = re.compile(r'[A-Za-z_][A-Za-z0-9_.\-\[\]"/]{0,159}\Z')
_ACTIONS = {
    ("no-op",),
    ("create",),
    ("read",),
    ("update",),
    ("delete",),
    ("delete", "create"),
    ("create", "delete"),
}
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


class IacChangeGraphError(ValueError):
    """A reduced change model or original-source replay is invalid."""


def _address(value: Any, label: str) -> str:
    if type(value) is not str or _ADDRESS.fullmatch(value) is None:
        raise IacChangeGraphError(f"{label} must be a bounded inert address")
    return value


def _address_list(value: Any, maximum: int, label: str) -> list[str]:
    rows = core.bounded_list(value, maximum, label)
    seen: set[str] = set()
    for item in rows:
        address = _address(item, label)
        if address in seen:
            raise IacChangeGraphError(f"Duplicate {label} address")
        seen.add(address)
    return rows


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "inventory_complete", "resources", "protected"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise IacChangeGraphError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["inventory_complete"], "inventory completeness")
    resources = core.bounded_list(model["resources"], MAX_RESOURCES, "resources")
    seen: set[str] = set()
    for index, row in enumerate(resources):
        item = core.exact(row, {"address", "actions", "depends_on"}, f"resource {index}")
        address = _address(item["address"], "resource address")
        if address in seen:
            raise IacChangeGraphError("Duplicate resource address")
        seen.add(address)
        actions = core.bounded_list(item["actions"], 2, "actions")
        if any(type(action) is not str for action in actions) or tuple(actions) not in _ACTIONS:
            raise IacChangeGraphError("Unsupported action sequence")
        _address_list(item["depends_on"], MAX_DEPENDENCIES, "dependency")
    _address_list(model["protected"], MAX_PROTECTED, "protected")
    return model, core.canonical(model)


def _cycles(resources: dict[str, dict]) -> list[dict[str, str]]:
    state: dict[str, int] = {}
    back_edges: set[tuple[str, str]] = set()

    def visit(address: str) -> None:
        state[address] = 1
        for dependency in sorted(resources[address]["depends_on"]):
            if dependency not in resources:
                continue
            if state.get(dependency) == 1:
                back_edges.add((address, dependency))
            elif state.get(dependency, 0) == 0:
                visit(dependency)
        state[address] = 2

    for address in sorted(resources):
        if state.get(address, 0) == 0:
            visit(address)
    return [
        {"issue": "declared_dependency_cycle", "address": address, "dependency": dependency}
        for address, dependency in sorted(back_edges)
    ]


def _derive(value: Any) -> dict:
    model, source_text = _model(value)
    resources = {row["address"]: row for row in model["resources"]}
    quality = _cycles(resources)
    for address in sorted(resources):
        for dependency in sorted(resources[address]["depends_on"]):
            if dependency not in resources:
                quality.append(
                    {
                        "issue": "undeclared_dependency",
                        "address": address,
                        "dependency": dependency,
                    }
                )
    impacts: list[dict[str, Any]] = []
    for protected in sorted(model["protected"]):
        if protected not in resources:
            quality.append({"issue": "undeclared_protected_resource", "address": protected})
            continue
        queue = deque([(protected, (protected,))])
        visited = {protected}
        while queue:
            address, path = queue.popleft()
            row = resources[address]
            if "delete" in row["actions"]:
                impacts.append(
                    {
                        "protected_address": protected,
                        "changed_address": address,
                        "actions": list(row["actions"]),
                        "declared_path": list(path),
                    }
                )
            for dependency in sorted(row["depends_on"]):
                if dependency in resources and dependency not in visited:
                    visited.add(dependency)
                    queue.append((dependency, (*path, dependency)))
    if impacts:
        disposition = "candidate_supplied_destructive_path"
    elif quality or not model["inventory_complete"] or not model["protected"]:
        disposition = "unknown"
    else:
        disposition = "no_declared_destructive_path"
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
        "inventory_complete_asserted": model["inventory_complete"],
        "resource_count": len(resources),
        "protected_count": len(model["protected"]),
        "declared_impacts": impacts,
        "model_quality_issues": quality,
        "candidate_count": len(impacts),
        "unknown_count": len(quality)
        + int(not model["inventory_complete"] or not model["protected"]),
        "disposition": disposition,
        "source_authenticated": False,
        "raw_plan_accepted": False,
        "terraform_executed": False,
        "state_read": False,
        "provider_contacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Only caller-selected, value-free resource addresses, actions and "
            "dependencies are read.",
            "The source inventory and dependency completeness are unsigned caller assertions.",
            "Declared paths do not prove provider effects, public exposure or exploitability.",
            "A missing path does not prove safety or absence of undeclared dependencies.",
            "Raw Terraform plans, configuration values, state, secrets and provider "
            "data are rejected.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="IAC-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class IacChangeGraphReport:
    """Unsigned supplied-graph projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise IacChangeGraphError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> IacChangeGraphReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_iac_change_graph(model: Any) -> IacChangeGraphReport:
    return IacChangeGraphReport._owned(_derive(model))


def verify_supplied_iac_change_graph(
    report: Any,
    *,
    model: Any,
) -> IacChangeGraphReport:
    if type(report) is not IacChangeGraphReport:
        raise IacChangeGraphError("Exact change-graph wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise IacChangeGraphError("Report differs from separate original model")
    return IacChangeGraphReport._owned(expected)


def verify_supplied_iac_change_graph_bytes(
    report_bytes: bytes,
    *,
    model: Any,
) -> IacChangeGraphReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise IacChangeGraphError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise IacChangeGraphError("Exported report differs from original replay")
    return IacChangeGraphReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-iac-change-graph",
        "inventory_complete": True,
        "resources": [
            {
                "address": "aws_security_group.edge",
                "actions": ["delete", "create"],
                "depends_on": [],
            },
            {
                "address": "aws_instance.web",
                "actions": ["no-op"],
                "depends_on": ["aws_security_group.edge"],
            },
        ],
        "protected": ["aws_instance.web"],
    }

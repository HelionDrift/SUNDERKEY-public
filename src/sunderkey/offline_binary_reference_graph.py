"""Project supplied binary function references without opening a binary."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "exploit_supplied_binary_reference_graph"
PROFILE_ID = "AOE-GE-D21-S16"
CAPABILITY_ID = "army.ge.d21.s16"
VECTOR_ID = "AV-GE-D21-S16-01"
WORK_PACKAGE_ID = "IWP2-AOE-GE-D21-S16"
WAVE_ID = "IW2-028"
COMMANDER_ID = "AOE-GE-D21-CMD"
GROUP_OWNER_ID = "AOE-HQ-07"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:974b798b7a63f870f6cba61fdc2545334c35a40dbdc779859d973a0296131ebd"
DOMAIN = "sunderkey.offline-binary-reference-graph.v1"
MAX_MODEL_BYTES = 131_072
MAX_REPORT_BYTES = 131_072
MAX_FUNCTIONS = 64
MAX_CALLS = 16
MAX_ENTRIES = 16
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process",
        "provider", "credentials", "target_interaction",
        "finding_publication", "qualification",
    )
}


class BinaryReferenceGraphError(ValueError):
    """The supplied reference graph or original-model replay is invalid."""


def _model(value: Any) -> tuple[dict, dict[str, tuple[str, ...]], tuple[str, ...], str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {
            "schema_version", "source_id", "function_inventory_complete",
            "entry_symbol_ids", "functions",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise BinaryReferenceGraphError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["function_inventory_complete"], "inventory completeness")
    graph = {}
    for item in core.bounded_list(model["functions"], MAX_FUNCTIONS, "functions"):
        row = core.exact(item, {"symbol_id", "call_symbol_ids"}, "function")
        symbol = core.identifier(row["symbol_id"], "symbol ID")
        if symbol in graph:
            raise BinaryReferenceGraphError("Duplicate function symbol")
        calls = tuple(
            core.identifier(call, "called symbol")
            for call in core.bounded_list(row["call_symbol_ids"], MAX_CALLS, "calls")
        )
        if len(calls) != len(set(calls)):
            raise BinaryReferenceGraphError("Duplicate call reference")
        graph[symbol] = tuple(sorted(calls))
    if not graph:
        raise BinaryReferenceGraphError("At least one function is required")
    entries = tuple(
        core.identifier(entry, "entry symbol")
        for entry in core.bounded_list(model["entry_symbol_ids"], MAX_ENTRIES, "entries")
    )
    if not entries or len(entries) != len(set(entries)):
        raise BinaryReferenceGraphError("Entries must be nonempty and unique")
    if not set(entries).issubset(graph):
        raise BinaryReferenceGraphError("Entry symbol is not in supplied inventory")
    for calls in graph.values():
        if not set(calls).issubset(graph):
            raise BinaryReferenceGraphError("Call reference is not in supplied inventory")
    return model, graph, tuple(sorted(entries)), core.canonical(model)


def _recursive_groups(graph: dict[str, tuple[str, ...]]) -> list[list[str]]:
    index = 0
    indices: dict[str, int] = {}
    lowlinks: dict[str, int] = {}
    stack: list[str] = []
    on_stack: set[str] = set()
    groups: list[list[str]] = []

    def visit(symbol: str) -> None:
        nonlocal index
        indices[symbol] = index
        lowlinks[symbol] = index
        index += 1
        stack.append(symbol)
        on_stack.add(symbol)
        for called in graph[symbol]:
            if called not in indices:
                visit(called)
                lowlinks[symbol] = min(lowlinks[symbol], lowlinks[called])
            elif called in on_stack:
                lowlinks[symbol] = min(lowlinks[symbol], indices[called])
        if lowlinks[symbol] == indices[symbol]:
            group = []
            while True:
                member = stack.pop()
                on_stack.remove(member)
                group.append(member)
                if member == symbol:
                    break
            if len(group) > 1 or symbol in graph[symbol]:
                groups.append(sorted(group))

    for symbol in sorted(graph):
        if symbol not in indices:
            visit(symbol)
    return sorted(groups)


def _derive(value: Any) -> dict:
    model, graph, entries, source_text = _model(value)
    reachable = set(entries)
    pending = list(entries)
    while pending:
        symbol = pending.pop()
        for called in graph[symbol]:
            if called not in reachable:
                reachable.add(called)
                pending.append(called)
    groups = _recursive_groups(graph)
    uncertainty = []
    if not model["function_inventory_complete"]:
        uncertainty.append("supplied_function_inventory_incomplete")
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
        "function_inventory_complete_asserted": model["function_inventory_complete"],
        "supplied_function_count": len(graph),
        "supplied_call_reference_count": sum(len(calls) for calls in graph.values()),
        "entry_symbol_ids": list(entries),
        "reachable_symbol_ids": sorted(reachable),
        "unreachable_symbol_ids": sorted(set(graph) - reachable),
        "recursive_symbol_groups": groups,
        "candidate_count": 0,
        "uncertainty": uncertainty,
        "unknown_count": len(uncertainty),
        "disposition": "unknown" if uncertainty else "supplied_reference_graph_projection",
        "source_authenticated": False,
        "binary_bytes_read": False,
        "references_disassembled_or_verified": False,
        "runtime_call_path_verified": False,
        "target_executed": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Function and call references are supplied assertions, not disassembly.",
            "Graph reachability is not an observed runtime call path.",
            "Recursive groups are graph cycles, not proven recursive execution.",
            "No binary bytes, process, target or finding are involved.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="BRG-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return report


@dataclass(frozen=True, slots=True, init=False)
class BinaryReferenceGraphReport:
    """Unsigned graph projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise BinaryReferenceGraphError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> BinaryReferenceGraphReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_binary_references(model: Any) -> BinaryReferenceGraphReport:
    return BinaryReferenceGraphReport._owned(_derive(model))


def verify_supplied_binary_references(
    report: Any, *, model: Any
) -> BinaryReferenceGraphReport:
    if type(report) is not BinaryReferenceGraphReport:
        raise BinaryReferenceGraphError("Exact graph wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise BinaryReferenceGraphError("Report differs from separate original model")
    return BinaryReferenceGraphReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-reference-graph",
        "function_inventory_complete": True,
        "entry_symbol_ids": ["entry"],
        "functions": [
            {"symbol_id": "entry", "call_symbol_ids": ["parse"]},
            {"symbol_id": "parse", "call_symbol_ids": ["helper"]},
            {"symbol_id": "helper", "call_symbol_ids": ["parse"]},
            {"symbol_id": "unused", "call_symbol_ids": []},
        ],
    }

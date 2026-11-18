"""Review a caller-supplied threat-scenario dependency graph offline."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "campaign_supplied_threat_scenario_graph"
PROFILE_ID = "AOE-GA-D04-S01"
CAPABILITY_ID = "campaign.threat-scenario-design"
VECTOR_ID = "AV-GA-D04-S01-01"
WORK_PACKAGE_ID = "IWP2-AOE-GA-D04-S01"
WAVE_ID = "IW2-002"
COMMANDER_ID = "AOE-GA-D04-CMD"
GROUP_OWNER_ID = "AOE-HQ-03"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:143ada798bc79602b72907d914c98bae974af4e47d1b5cb31938a27f85574781"
DOMAIN = "sunderkey.offline-threat-scenario-graph.v1"
MAX_MODEL_BYTES = 131_072
MAX_REPORT_BYTES = 131_072
MAX_STAGES = 64
MAX_PREREQUISITES = 16
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process",
        "provider", "credentials", "target_interaction",
        "finding_publication", "qualification",
    )
}


class ThreatScenarioGraphError(ValueError):
    """The supplied graph or its original-model replay is invalid."""


def _model(value: Any) -> tuple[dict, dict[str, tuple[str, ...]], dict[str, str], str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "stage_inventory_complete", "stages"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise ThreatScenarioGraphError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["stage_inventory_complete"], "inventory completeness")
    graph: dict[str, tuple[str, ...]] = {}
    evidence: dict[str, str] = {}
    for item in core.bounded_list(model["stages"], MAX_STAGES, "stages"):
        row = core.exact(
            item, {"stage_id", "prerequisite_stage_ids", "evidence_status"}, "stage"
        )
        stage = core.identifier(row["stage_id"], "stage ID")
        if stage in graph:
            raise ThreatScenarioGraphError("Duplicate stage ID")
        prerequisites = tuple(
            core.identifier(parent, "prerequisite stage ID")
            for parent in core.bounded_list(
                row["prerequisite_stage_ids"], MAX_PREREQUISITES, "prerequisites"
            )
        )
        if len(prerequisites) != len(set(prerequisites)) or stage in prerequisites:
            raise ThreatScenarioGraphError("Duplicate or self prerequisite")
        graph[stage] = tuple(sorted(prerequisites))
        evidence[stage] = core.choice(
            row["evidence_status"], {"supplied", "missing", "unknown"}, "evidence status"
        )
    if not graph:
        raise ThreatScenarioGraphError("At least one stage is required")
    if any(not set(parents).issubset(graph) for parents in graph.values()):
        raise ThreatScenarioGraphError("Prerequisite is outside supplied stage inventory")
    return model, graph, evidence, core.canonical(model)


def _topological_order(graph: dict[str, tuple[str, ...]]) -> list[str]:
    pending = set(graph)
    ordered: list[str] = []
    while pending:
        ready = sorted(stage for stage in pending if set(graph[stage]).issubset(ordered))
        if not ready:
            raise ThreatScenarioGraphError("Scenario dependency cycle")
        ordered.extend(ready)
        pending.difference_update(ready)
    return ordered


def _derive(value: Any) -> dict:
    model, graph, evidence, source_text = _model(value)
    order = _topological_order(graph)
    closure: dict[str, set[str]] = {}
    stages = []
    for stage in order:
        ancestors = set(graph[stage])
        for parent in graph[stage]:
            ancestors.update(closure[parent])
        closure[stage] = ancestors
        parent_states = {evidence[parent] for parent in ancestors}
        prerequisite_disposition = (
            "blocked_by_supplied_gap" if "missing" in parent_states
            else "unknown" if "unknown" in parent_states
            else "supplied_prerequisites_only"
        )
        stages.append({
            "stage_id": stage,
            "evidence_status_asserted": evidence[stage],
            "direct_prerequisite_stage_ids": list(graph[stage]),
            "transitive_prerequisite_stage_ids": sorted(ancestors),
            "prerequisite_disposition": prerequisite_disposition,
        })
    unknown = []
    if not model["stage_inventory_complete"]:
        unknown.append("supplied_stage_inventory_incomplete")
    if any(state == "unknown" for state in evidence.values()):
        unknown.append("one_or_more_stage_evidence_states_unknown")
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
        "stage_inventory_complete_asserted": model["stage_inventory_complete"],
        "supplied_stage_count": len(graph),
        "topological_stage_ids": order,
        "stages": stages,
        "candidate_count": 0,
        "uncertainty": unknown,
        "unknown_count": len(unknown),
        "disposition": "unknown" if unknown else "supplied_scenario_projection",
        "source_authenticated": False,
        "evidence_verified": False,
        "scenario_executed": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Stage inventory and evidence states are caller-supplied assertions.",
            "Graph reachability is not proof of a feasible attack path.",
            "Prerequisite disposition is a planning projection, not authorization.",
            "No target, exploit, credential or live action is involved.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="TSG-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return report


@dataclass(frozen=True, slots=True, init=False)
class ThreatScenarioGraphReport:
    """Unsigned projection requiring separate original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise ThreatScenarioGraphError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> ThreatScenarioGraphReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_threat_scenario(model: Any) -> ThreatScenarioGraphReport:
    return ThreatScenarioGraphReport._owned(_derive(model))


def verify_supplied_threat_scenario(
    report: Any, *, model: Any
) -> ThreatScenarioGraphReport:
    if type(report) is not ThreatScenarioGraphReport:
        raise ThreatScenarioGraphError("Exact scenario wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise ThreatScenarioGraphError("Report differs from separate original model")
    return ThreatScenarioGraphReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-scenario",
        "stage_inventory_complete": True,
        "stages": [
            {"stage_id": "observe", "prerequisite_stage_ids": [], "evidence_status": "supplied"},
            {
                "stage_id": "hypothesis", "prerequisite_stage_ids": ["observe"],
                "evidence_status": "unknown",
            },
            {
                "stage_id": "review", "prerequisite_stage_ids": ["hypothesis"],
                "evidence_status": "missing",
            },
        ],
    }

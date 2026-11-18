"""Project controls over a supplied, synthetic initial-access dependency chain."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core
from .offline_threat_scenario_graph import analyze_supplied_threat_scenario

COMPONENT_ID = "campaign_supplied_initial_access_chain_controls"
PROFILE_ID = "AOE-GA-D04-S02"
CAPABILITY_ID = "army.ga.d04.s02"
VECTOR_ID = "AV-GA-D04-S02-01"
WORK_PACKAGE_ID = "IWP2-AOE-GA-D04-S02"
WAVE_ID = "IW2-003"
COMMANDER_ID = "AOE-GA-D04-CMD"
GROUP_OWNER_ID = "AOE-HQ-03"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:c87a8db32df7afc1dc7338406f60b04cd78adc64b4056ef554dc6bd48dd65f5c"
DOMAIN = "sunderkey.offline-initial-access-chain-controls.v1"
MAX_MODEL_BYTES = 131_072
MAX_REPORT_BYTES = 131_072
MAX_STAGES = 64
TIERS = ("R0", "R1", "R2", "R3")
CONTROL_STATES = {"asserted", "missing", "unknown"}
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class InitialAccessChainControlError(ValueError):
    """A supplied chain control model or original-model replay is invalid."""


def _derive(value: Any) -> dict:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {
            "schema_version", "source_id", "synthetic_fixture", "scenario_model",
            "entry_stage_id", "objective_stage_id", "maximum_declared_tier",
            "stage_controls",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise InitialAccessChainControlError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if model["synthetic_fixture"] is not True:
        raise InitialAccessChainControlError("Only synthetic fixtures are accepted")
    maximum_tier = core.choice(model["maximum_declared_tier"], set(TIERS), "tier")
    entry = core.identifier(model["entry_stage_id"], "entry stage ID")
    objective = core.identifier(model["objective_stage_id"], "objective stage ID")
    scenario = analyze_supplied_threat_scenario(model["scenario_model"]).to_dict()
    stage_index = {row["stage_id"]: row for row in scenario["stages"]}
    if entry not in stage_index or objective not in stage_index:
        raise InitialAccessChainControlError("Entry or objective is outside stage inventory")
    controls: dict[str, dict] = {}
    for row in core.bounded_list(model["stage_controls"], MAX_STAGES, "stage controls"):
        control = core.exact(
            row,
            {"stage_id", "declared_tier", "authorization_status", "stop_rule_status"},
            "stage control",
        )
        stage_id = core.identifier(control["stage_id"], "stage ID")
        if stage_id in controls:
            raise InitialAccessChainControlError("Duplicate stage control")
        controls[stage_id] = {
            "stage_id": stage_id,
            "declared_tier": core.choice(control["declared_tier"], set(TIERS), "tier"),
            "authorization_status": core.choice(
                control["authorization_status"], CONTROL_STATES, "authorization"
            ),
            "stop_rule_status": core.choice(
                control["stop_rule_status"], CONTROL_STATES, "stop rule"
            ),
        }
    if set(controls) != set(stage_index):
        raise InitialAccessChainControlError("Stage controls must exactly cover inventory")
    dependency_closure = set(stage_index[objective]["transitive_prerequisite_stage_ids"])
    dependency_closure.add(objective)
    entry_in_closure = entry in dependency_closure
    ordered_chain = [
        stage_id for stage_id in scenario["topological_stage_ids"]
        if stage_id in dependency_closure
    ]
    rows = []
    missing = []
    unknown = []
    for stage_id in ordered_chain:
        stage = stage_index[stage_id]
        control = controls[stage_id]
        gaps = []
        uncertainties = []
        if stage["evidence_status_asserted"] == "missing":
            gaps.append("stage_evidence_missing")
        elif stage["evidence_status_asserted"] == "unknown":
            uncertainties.append("stage_evidence_unknown")
        if TIERS.index(control["declared_tier"]) > TIERS.index(maximum_tier):
            gaps.append("declared_tier_exceeds_supplied_ceiling")
        for field, label in (
            ("authorization_status", "authorization"),
            ("stop_rule_status", "stop_rule"),
        ):
            if control[field] == "missing":
                gaps.append(f"{label}_missing")
            elif control[field] == "unknown":
                uncertainties.append(f"{label}_unknown")
        if gaps:
            missing.append(stage_id)
        if uncertainties:
            unknown.append(stage_id)
        rows.append({
            "stage_id": stage_id,
            "declared_tier": control["declared_tier"],
            "stage_evidence_status_asserted": stage["evidence_status_asserted"],
            "authorization_status_asserted": control["authorization_status"],
            "stop_rule_status_asserted": control["stop_rule_status"],
            "gap_reasons": gaps,
            "uncertainty_reasons": uncertainties,
        })
    uncertainty = []
    if not scenario["stage_inventory_complete_asserted"]:
        uncertainty.append("stage_inventory_incomplete")
    if unknown:
        uncertainty.append("one_or_more_chain_control_states_unknown")
    if not entry_in_closure:
        disposition = "entry_not_in_objective_dependency_closure"
    elif missing:
        disposition = "supplied_chain_control_gap"
    elif uncertainty:
        disposition = "unknown"
    else:
        disposition = "supplied_chain_controls_only"
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
        "source_model_sha256": core.digest(core.canonical(model).encode("ascii")),
        "base_scenario_report_id": scenario["report_id"],
        "base_scenario_report_sha256": scenario["report_sha256"],
        "synthetic_fixture_asserted": True,
        "entry_stage_id": entry,
        "objective_stage_id": objective,
        "entry_in_objective_dependency_closure": entry_in_closure,
        "maximum_declared_tier": maximum_tier,
        "objective_dependency_stage_ids": ordered_chain,
        "stage_control_projections": rows,
        "gap_stage_ids": missing,
        "uncertain_stage_ids": unknown,
        "candidate_count": 0,
        "uncertainty": uncertainty,
        "unknown_count": len(uncertainty),
        "disposition": disposition,
        "source_authenticated": False,
        "authorization_verified": False,
        "exercise_approved": False,
        "chain_executed": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Stages, control statuses, and ceiling are caller-supplied assertions.",
            "A dependency closure is not a feasible or authorized access path.",
            "An asserted authorization status is not verified action authority.",
            "No technique, credential, target, or delivery action is generated.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="IAC-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return report


@dataclass(frozen=True, slots=True, init=False)
class InitialAccessChainControlReport:
    """Unsigned projection requiring separate original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise InitialAccessChainControlError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> InitialAccessChainControlReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_initial_access_chain(model: Any) -> InitialAccessChainControlReport:
    return InitialAccessChainControlReport._owned(_derive(model))


def verify_supplied_initial_access_chain(
    report: Any, *, model: Any
) -> InitialAccessChainControlReport:
    if type(report) is not InitialAccessChainControlReport:
        raise InitialAccessChainControlError("Exact chain wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise InitialAccessChainControlError("Report differs from separate original model")
    return InitialAccessChainControlReport._owned(expected)


def component_fixture() -> dict:
    from .offline_threat_scenario_graph import component_fixture as scenario_fixture

    scenario = scenario_fixture()
    return {
        "schema_version": 1,
        "source_id": "synthetic-initial-access-chain",
        "synthetic_fixture": True,
        "scenario_model": scenario,
        "entry_stage_id": "observe",
        "objective_stage_id": "review",
        "maximum_declared_tier": "R0",
        "stage_controls": [
            {
                "stage_id": stage["stage_id"],
                "declared_tier": "R0",
                "authorization_status": "asserted",
                "stop_rule_status": "asserted",
            }
            for stage in scenario["stages"]
        ],
    }

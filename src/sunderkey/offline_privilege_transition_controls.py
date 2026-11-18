"""Project review gates over supplied synthetic privilege-tier transitions."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core
from .offline_threat_scenario_graph import analyze_supplied_threat_scenario

COMPONENT_ID = "campaign_supplied_privilege_transition_controls"
PROFILE_ID = "AOE-GA-D04-S07"
CAPABILITY_ID = "army.ga.d04.s07"
VECTOR_ID = "AV-GA-D04-S07-01"
WORK_PACKAGE_ID = "IWP2-AOE-GA-D04-S07"
WAVE_ID = "IW2-008"
COMMANDER_ID = "AOE-GA-D04-CMD"
GROUP_OWNER_ID = "AOE-HQ-03"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:20a8989399cc383995ae6fc26d849cda6ce27c033758e9e0dcbfa2c48d1d6ac3"
DOMAIN = "sunderkey.offline-privilege-transition-controls.v1"
MAX_MODEL_BYTES = 131_072
MAX_REPORT_BYTES = 131_072
MAX_STAGES = 64
TIERS = ("P0", "P1", "P2", "P3")
GATE_STATES = {"asserted", "missing", "unknown"}
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class PrivilegeTransitionControlError(ValueError):
    """A supplied transition model or original-model replay is invalid."""


def _derive(value: Any) -> dict:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {
            "schema_version", "source_id", "synthetic_fixture",
            "scenario_model", "stage_privileges",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise PrivilegeTransitionControlError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if model["synthetic_fixture"] is not True:
        raise PrivilegeTransitionControlError("Only synthetic fixtures are accepted")
    scenario = analyze_supplied_threat_scenario(model["scenario_model"]).to_dict()
    stages = {row["stage_id"]: row for row in scenario["stages"]}
    privileges: dict[str, dict] = {}
    for item in core.bounded_list(
        model["stage_privileges"], MAX_STAGES, "stage privileges"
    ):
        row = core.exact(
            item,
            {"stage_id", "declared_privilege_tier", "escalation_review_status"},
            "stage privilege",
        )
        stage_id = core.identifier(row["stage_id"], "stage ID")
        if stage_id in privileges:
            raise PrivilegeTransitionControlError("Duplicate stage privilege")
        privileges[stage_id] = {
            "tier": core.choice(
                row["declared_privilege_tier"], set(TIERS), "privilege tier"
            ),
            "gate": core.choice(
                row["escalation_review_status"], GATE_STATES, "review status"
            ),
        }
    if set(privileges) != set(stages):
        raise PrivilegeTransitionControlError("Privileges must exactly cover stages")
    transitions = []
    missing = []
    unknown = []
    for stage_id in scenario["topological_stage_ids"]:
        stage = stages[stage_id]
        for parent in stage["direct_prerequisite_stage_ids"]:
            previous = privileges[parent]["tier"]
            current = privileges[stage_id]["tier"]
            increase = TIERS.index(current) > TIERS.index(previous)
            gate = privileges[stage_id]["gate"]
            if increase and gate == "missing":
                missing.append([parent, stage_id])
            elif increase and gate == "unknown":
                unknown.append([parent, stage_id])
            transitions.append({
                "from_stage_id": parent,
                "to_stage_id": stage_id,
                "from_privilege_tier_asserted": previous,
                "to_privilege_tier_asserted": current,
                "tier_increase_declared": increase,
                "review_status_asserted": gate,
                "review_gap": increase and gate == "missing",
                "review_unknown": increase and gate == "unknown",
            })
    high_roots = sorted(
        stage_id for stage_id, stage in stages.items()
        if not stage["direct_prerequisite_stage_ids"]
        and privileges[stage_id]["tier"] != "P0"
    )
    uncertainty = []
    if not scenario["stage_inventory_complete_asserted"]:
        uncertainty.append("supplied_stage_inventory_incomplete")
    if high_roots:
        uncertainty.append("root_privilege_origin_unassessed")
    if unknown:
        uncertainty.append("one_or_more_escalation_reviews_unknown")
    if any(
        row["evidence_status_asserted"] != "supplied"
        for row in stages.values()
    ):
        uncertainty.append("one_or_more_stage_evidence_states_not_supplied")
    disposition = (
        "supplied_review_gap" if missing else
        "unknown" if uncertainty else
        "supplied_transition_reviews_only"
    )
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
        "stage_inventory_complete_asserted": scenario["stage_inventory_complete_asserted"],
        "transition_projections": transitions,
        "review_gap_stage_pairs": missing,
        "review_unknown_stage_pairs": unknown,
        "high_tier_root_stage_ids": high_roots,
        "candidate_count": 0,
        "uncertainty": uncertainty,
        "unknown_count": len(uncertainty),
        "disposition": disposition,
        "source_authenticated": False,
        "privileges_verified": False,
        "review_authority_verified": False,
        "escalation_executed": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Stages, privilege tiers, review states and evidence are synthetic assertions.",
            "A tier increase in the graph is not a real privilege escalation.",
            "An asserted review status is not verified action authority.",
            "No method, payload, credential, target or live action is produced.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="PTC-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return report


@dataclass(frozen=True, slots=True, init=False)
class PrivilegeTransitionControlReport:
    """Unsigned transition projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise PrivilegeTransitionControlError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> PrivilegeTransitionControlReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_privilege_transitions(model: Any) -> PrivilegeTransitionControlReport:
    return PrivilegeTransitionControlReport._owned(_derive(model))


def verify_supplied_privilege_transitions(
    report: Any, *, model: Any
) -> PrivilegeTransitionControlReport:
    if type(report) is not PrivilegeTransitionControlReport:
        raise PrivilegeTransitionControlError("Exact transition wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise PrivilegeTransitionControlError("Report differs from separate original model")
    return PrivilegeTransitionControlReport._owned(expected)


def component_fixture() -> dict:
    from .offline_threat_scenario_graph import component_fixture as scenario_fixture

    scenario = scenario_fixture()
    return {
        "schema_version": 1,
        "source_id": "synthetic-privilege-transitions",
        "synthetic_fixture": True,
        "scenario_model": scenario,
        "stage_privileges": [
            {"stage_id": "observe", "declared_privilege_tier": "P0",
             "escalation_review_status": "asserted"},
            {"stage_id": "hypothesis", "declared_privilege_tier": "P1",
             "escalation_review_status": "missing"},
            {"stage_id": "review", "declared_privilege_tier": "P2",
             "escalation_review_status": "unknown"},
        ],
    }

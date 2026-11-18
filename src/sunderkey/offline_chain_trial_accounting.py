"""Account for supplied sequential trial outcomes without running a chain."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "exploit_supplied_chain_trial_accounting"
PROFILE_ID = "AOE-GE-D21-S18"
CAPABILITY_ID = "army.ge.d21.s18"
VECTOR_ID = "AV-GE-D21-S18-01"
WORK_PACKAGE_ID = "IWP2-AOE-GE-D21-S18"
WAVE_ID = "IW2-030"
COMMANDER_ID = "AOE-GE-D21-CMD"
GROUP_OWNER_ID = "AOE-HQ-07"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:8e6be81ceb42239011344e1148301f615f88b714a6d14dfd9bf9b202c5ed65e5"
DOMAIN = "sunderkey.offline-chain-trial-accounting.v1"
MAX_MODEL_BYTES = 131_072
MAX_REPORT_BYTES = 131_072
MAX_STAGES = 8
MAX_TRIALS = 128
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process",
        "provider", "credentials", "target_interaction",
        "finding_publication", "qualification",
    )
}


class ChainTrialAccountingError(ValueError):
    """The supplied trial inventory or original-model replay is invalid."""


def _model(value: Any) -> tuple[dict, list[str], str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "trial_inventory_complete", "stage_ids", "trials"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise ChainTrialAccountingError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["trial_inventory_complete"], "trial inventory completeness")
    stages = [
        core.identifier(stage, "stage ID")
        for stage in core.bounded_list(model["stage_ids"], MAX_STAGES, "stages")
    ]
    if not stages or len(stages) != len(set(stages)):
        raise ChainTrialAccountingError("Stages must be nonempty and unique")
    trials = core.bounded_list(model["trials"], MAX_TRIALS, "trials")
    if not trials:
        raise ChainTrialAccountingError("At least one trial is required")
    seen = set()
    for item in trials:
        row = core.exact(item, {"trial_id", "environment_id", "stage_outcomes"}, "trial")
        trial_id = core.identifier(row["trial_id"], "trial ID")
        if trial_id in seen:
            raise ChainTrialAccountingError("Duplicate trial ID")
        seen.add(trial_id)
        core.identifier(row["environment_id"], "environment ID")
        outcomes = core.bounded_list(row["stage_outcomes"], MAX_STAGES, "outcomes")
        if len(outcomes) != len(stages):
            raise ChainTrialAccountingError("Trial must align with every stage")
        failed = False
        for outcome in outcomes:
            if failed:
                if outcome is not None:
                    raise ChainTrialAccountingError("Later stage must be unattempted after failure")
            elif type(outcome) is not bool:
                raise ChainTrialAccountingError("Attempted stage needs native Boolean outcome")
            elif not outcome:
                failed = True
    return model, stages, core.canonical(model)


def _derive(value: Any) -> dict:
    model, stages, source_text = _model(value)
    attempted = [0] * len(stages)
    succeeded = [0] * len(stages)
    first_failures = [0] * len(stages)
    complete_successes = 0
    environment_counts: dict[str, list[int]] = {}
    for row in model["trials"]:
        outcomes = row["stage_outcomes"]
        environment = row["environment_id"]
        counts = environment_counts.setdefault(environment, [0, 0])
        counts[0] += 1
        if all(outcome is True for outcome in outcomes):
            complete_successes += 1
            counts[1] += 1
        for index, outcome in enumerate(outcomes):
            if outcome is None:
                break
            attempted[index] += 1
            if outcome:
                succeeded[index] += 1
            else:
                first_failures[index] += 1
                break
    stage_summary = [
        {
            "stage_id": stage,
            "attempted_count": attempted[index],
            "success_count": succeeded[index],
            "first_failure_count": first_failures[index],
        }
        for index, stage in enumerate(stages)
    ]
    environment_summary = [
        {
            "environment_id": environment,
            "trial_count": counts[0],
            "complete_success_count": counts[1],
        }
        for environment, counts in sorted(environment_counts.items())
    ]
    uncertainty = []
    if not model["trial_inventory_complete"]:
        uncertainty.append("supplied_trial_inventory_incomplete")
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
        "trial_inventory_complete_asserted": model["trial_inventory_complete"],
        "trial_count": len(model["trials"]),
        "stage_count": len(stages),
        "complete_success_count": complete_successes,
        "first_failure_count": sum(first_failures),
        "stage_summary": stage_summary,
        "environment_summary": environment_summary,
        "candidate_count": 0,
        "uncertainty": uncertainty,
        "unknown_count": len(uncertainty),
        "disposition": "unknown" if uncertainty else "supplied_chain_trials_accounted",
        "source_authenticated": False,
        "trial_execution_verified": False,
        "environment_comparability_verified": False,
        "exploit_reliability_established": False,
        "target_executed": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Trial outcomes, stage order and environment labels are supplied assertions.",
            "Counts are not statistical reliability estimates or independent repetitions.",
            "No target, exploit chain, mitigation bypass or restoration is executed.",
            "No finding, candidate or qualification is established.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="CTA-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return report


@dataclass(frozen=True, slots=True, init=False)
class ChainTrialAccountingReport:
    """Unsigned trial accounting requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise ChainTrialAccountingError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> ChainTrialAccountingReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_chain_trials(model: Any) -> ChainTrialAccountingReport:
    return ChainTrialAccountingReport._owned(_derive(model))


def verify_supplied_chain_trials(
    report: Any, *, model: Any
) -> ChainTrialAccountingReport:
    if type(report) is not ChainTrialAccountingReport:
        raise ChainTrialAccountingError("Exact trial-accounting wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise ChainTrialAccountingError("Report differs from separate original model")
    return ChainTrialAccountingReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-chain-trials",
        "trial_inventory_complete": True,
        "stage_ids": ["prepare", "exercise", "restore"],
        "trials": [
            {"trial_id": "t1", "environment_id": "fixture_a",
             "stage_outcomes": [True, True, True]},
            {"trial_id": "t2", "environment_id": "fixture_a",
             "stage_outcomes": [True, False, None]},
            {"trial_id": "t3", "environment_id": "fixture_b",
             "stage_outcomes": [False, None, None]},
        ],
    }

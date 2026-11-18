"""Compare synthetic direct override claims with declared higher-priority constraints."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "model_supplied_direct_instruction_boundary_projection"
PROFILE_ID = "AOE-GD-D20-S09"
CAPABILITY_ID = "army.gd.d20.s09"
VECTOR_ID = "AV-GD-D20-S09-01"
WORK_PACKAGE_ID = "IWP2-AOE-GD-D20-S09"
WAVE_ID = "IW2-013"
COMMANDER_ID = "AOE-GD-D20-CMD"
GROUP_OWNER_ID = "AOE-HQ-06"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-35"
BLUEPRINT_SHA256 = "sha256:07dbb7b3a8fe85b6e9a6c1a1ccd8df817b2a7b80c4334ea331f7200bb5af74ce"
DOMAIN = "sunderkey.offline-direct-instruction-boundary.v1"
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class DirectInstructionBoundaryError(ValueError):
    """A supplied direct-instruction model or original-model replay is invalid."""


def _derive(value: Any) -> dict:
    core.validate_tree(value, maximum=131_072)
    model = core.exact(json.loads(core.canonical(value)), {
        "schema_version", "source_id", "synthetic_fixture", "transcript_complete",
        "higher_priority_constraint_ids", "user_attempts",
    }, "model")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise DirectInstructionBoundaryError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if not core.boolean(model["synthetic_fixture"], "synthetic fixture"):
        raise DirectInstructionBoundaryError("Only synthetic fixtures are accepted")
    complete = core.boolean(model["transcript_complete"], "transcript completeness")
    constraints = [
        core.identifier(item, "constraint ID")
        for item in core.bounded_list(
            model["higher_priority_constraint_ids"], 32, "higher-priority constraints"
        )
    ]
    if not constraints or len(constraints) != len(set(constraints)):
        raise DirectInstructionBoundaryError("Constraint IDs must be nonempty and unique")
    attempts = core.bounded_list(model["user_attempts"], 64, "user attempts")
    if not attempts:
        raise DirectInstructionBoundaryError("At least one attempt is required")
    rows = []
    seen = set()
    for item in attempts:
        row = core.exact(item, {
            "attempt_ref", "target_constraint_id", "override_claimed", "outcome_declared",
        }, "user attempt")
        attempt_ref = core.identifier(row["attempt_ref"], "opaque attempt reference")
        constraint = core.identifier(row["target_constraint_id"], "constraint ID")
        if attempt_ref in seen:
            raise DirectInstructionBoundaryError("Duplicate attempt reference")
        seen.add(attempt_ref)
        if constraint not in constraints:
            raise DirectInstructionBoundaryError("Attempt references an unknown constraint")
        override = core.boolean(row["override_claimed"], "override declaration")
        outcome = core.choice(
            row["outcome_declared"], {"declined", "followed", "unknown"}, "declared outcome"
        )
        rows.append({
            "attempt_ref": attempt_ref,
            "target_constraint_id": constraint,
            "override_claimed": override,
            "outcome_declared": outcome,
            "declared_boundary_conflict": override and outcome == "followed",
        })
    rows.sort(key=lambda row: row["attempt_ref"])
    conflicts = [row["attempt_ref"] for row in rows if row["declared_boundary_conflict"]]
    unknown = [] if complete else ["supplied_transcript_incomplete"]
    if any(row["outcome_declared"] == "unknown" for row in rows):
        unknown.append("attempt_outcome_unknown")
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
        "synthetic_fixture_asserted": True,
        "transcript_complete_asserted": complete,
        "attempt_projections": rows,
        "declared_boundary_conflict_attempt_refs": conflicts,
        "candidate_count": 0,
        "uncertainty": unknown,
        "unknown_count": len(unknown),
        "disposition": "unknown" if unknown else "supplied_direct_instruction_projection",
        "source_authenticated": False,
        "prompt_text_processed": False,
        "model_called": False,
        "jailbreak_verified": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Constraints, override claims, outcomes, and completeness are synthetic assertions.",
            "No prompt text, model response, or provider call is accepted or produced.",
            "A declared conflict does not prove a jailbreak, model behavior, or impact.",
            "No model, provider, credential, network, or target is accessed.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="DIB-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=131_072)
    return report


@dataclass(frozen=True, slots=True, init=False)
class DirectInstructionBoundaryReport:
    """Unsigned direct-boundary projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise DirectInstructionBoundaryError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> DirectInstructionBoundaryReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_direct_instruction_boundary(model: Any) -> DirectInstructionBoundaryReport:
    return DirectInstructionBoundaryReport._owned(_derive(model))


def verify_supplied_direct_instruction_boundary(
    report: Any, *, model: Any
) -> DirectInstructionBoundaryReport:
    if type(report) is not DirectInstructionBoundaryReport:
        raise DirectInstructionBoundaryError("Exact direct-boundary wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise DirectInstructionBoundaryError("Report differs from separate original model")
    return DirectInstructionBoundaryReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-direct-instruction-boundary",
        "synthetic_fixture": True,
        "transcript_complete": True,
        "higher_priority_constraint_ids": ["constraint-a"],
        "user_attempts": [{
            "attempt_ref": "attempt-opaque-a", "target_constraint_id": "constraint-a",
            "override_claimed": True, "outcome_declared": "followed",
        }],
    }

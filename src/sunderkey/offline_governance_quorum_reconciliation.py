"""Reconcile supplied governance outcomes with explicit vote-count rules."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "governance_supplied_quorum_reconciliation"
PROFILE_ID = "AOE-GB-D10-S11"
CAPABILITY_ID = "army.gb.d10.s11"
VECTOR_ID = "AV-GB-D10-S11-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D10-S11"
WAVE_ID = "IW2-011"
COMMANDER_ID = "AOE-GB-D10-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:20ba4a4c6da8c80b3ce9a8ea36b1f75014064e31b9ad0deacfb759ecc887d8cc"
DOMAIN = "sunderkey.offline-governance-quorum-reconciliation.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
QUORUM_MODES = {"for_only", "for_and_abstain", "all_votes"}
APPROVAL_MODES = {"for_strictly_exceeds_against", "for_share_threshold"}
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


class GovernanceQuorumReconciliationError(ValueError):
    """A supplied governance vote model or replay is invalid."""


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "proposals"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise GovernanceQuorumReconciliationError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    proposals = core.bounded_list(model["proposals"], 32, "proposals")
    if not proposals:
        raise GovernanceQuorumReconciliationError("At least one proposal is required")
    seen: set[str] = set()
    for item in proposals:
        row = core.exact(
            item,
            {
                "proposal_id",
                "snapshot_voting_power",
                "for_votes",
                "against_votes",
                "abstain_votes",
                "quorum_basis_points",
                "quorum_mode",
                "approval_mode",
                "approval_basis_points",
                "declared_passed",
                "snapshot_complete",
            },
            "proposal",
        )
        proposal_id = core.identifier(row["proposal_id"], "proposal ID")
        if proposal_id in seen:
            raise GovernanceQuorumReconciliationError("Duplicate proposal ID")
        seen.add(proposal_id)
        for key in ("snapshot_voting_power", "for_votes", "against_votes", "abstain_votes"):
            count = row[key]
            if type(count) is not int or not 0 <= count <= 1_000_000_000:
                raise GovernanceQuorumReconciliationError("Voting power must be bounded integers")
        if row["snapshot_voting_power"] == 0 or (
            row["for_votes"] + row["against_votes"] + row["abstain_votes"]
            > row["snapshot_voting_power"]
        ):
            raise GovernanceQuorumReconciliationError("Votes exceed snapshot voting power")
        for key in ("quorum_basis_points", "approval_basis_points"):
            value_bp = row[key]
            if type(value_bp) is not int or not 0 <= value_bp <= 10_000:
                raise GovernanceQuorumReconciliationError("Vote thresholds must be basis points")
        core.choice(row["quorum_mode"], QUORUM_MODES, "quorum mode")
        core.choice(row["approval_mode"], APPROVAL_MODES, "approval mode")
        if (
            row["approval_mode"] == "for_strictly_exceeds_against"
            and row["approval_basis_points"] != 0
        ):
            raise GovernanceQuorumReconciliationError("Strict approval mode has no share threshold")
        core.boolean(row["declared_passed"], "declared outcome")
        core.boolean(row["snapshot_complete"], "snapshot completeness")
    return model, core.canonical(model)


def _quorum_votes(row: dict) -> int:
    if row["quorum_mode"] == "for_only":
        return row["for_votes"]
    if row["quorum_mode"] == "for_and_abstain":
        return row["for_votes"] + row["abstain_votes"]
    return row["for_votes"] + row["against_votes"] + row["abstain_votes"]


def _derive(value: Any) -> dict:
    model, model_text = _model(value)
    projections = []
    for row in model["proposals"]:
        quorum_votes = _quorum_votes(row)
        quorum_met = (
            quorum_votes * 10_000 >= row["quorum_basis_points"] * row["snapshot_voting_power"]
        )
        if row["approval_mode"] == "for_strictly_exceeds_against":
            approval_met: bool | None = row["for_votes"] > row["against_votes"]
        else:
            decisive_votes = row["for_votes"] + row["against_votes"]
            approval_met = (
                None
                if decisive_votes == 0
                else row["for_votes"] * 10_000 >= row["approval_basis_points"] * decisive_votes
            )
        computed = None if approval_met is None else quorum_met and approval_met
        disposition = (
            "unknown"
            if not row["snapshot_complete"] or computed is None
            else "candidate_declared_governance_outcome_mismatch"
            if computed != row["declared_passed"]
            else "declared_outcome_reconciles"
        )
        projections.append(
            {
                "proposal_id": row["proposal_id"],
                "quorum_counted_votes": quorum_votes,
                "quorum_met": quorum_met,
                "approval_met": approval_met,
                "computed_passed": computed,
                "disposition": disposition,
            }
        )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(model_text.encode("ascii")),
        "proposal_count": len(model["proposals"]),
        "proposal_projections": projections,
        "candidate_count": sum(row["disposition"].startswith("candidate_") for row in projections),
        "unknown_count": sum(row["disposition"] == "unknown" for row in projections),
        "source_authenticated": False,
        "chain_queried": False,
        "governance_execution_verified": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Snapshot power, counted votes, rules and declared outcomes are caller-supplied.",
            "Custom counting, delegation, veto, timelock and execution rules are not evaluated.",
            "A mismatch is a supplied-record contradiction, not proof of on-chain "
            "governance abuse.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="GQR-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class GovernanceQuorumReconciliationReport:
    """Unsigned vote projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise GovernanceQuorumReconciliationError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> GovernanceQuorumReconciliationReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_governance_quorum(model: Any) -> GovernanceQuorumReconciliationReport:
    return GovernanceQuorumReconciliationReport._owned(_derive(model))


def verify_supplied_governance_quorum(
    report: Any, *, model: Any
) -> GovernanceQuorumReconciliationReport:
    if type(report) is not GovernanceQuorumReconciliationReport:
        raise GovernanceQuorumReconciliationError("Exact governance wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise GovernanceQuorumReconciliationError("Report differs from separate original model")
    return GovernanceQuorumReconciliationReport._owned(expected)


def verify_supplied_governance_quorum_bytes(
    report_bytes: bytes, *, model: Any
) -> GovernanceQuorumReconciliationReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise GovernanceQuorumReconciliationError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise GovernanceQuorumReconciliationError("Exported report differs from original replay")
    return GovernanceQuorumReconciliationReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-governance-votes",
        "proposals": [
            {
                "proposal_id": "proposal-one",
                "snapshot_voting_power": 1_000,
                "for_votes": 400,
                "against_votes": 100,
                "abstain_votes": 100,
                "quorum_basis_points": 5_000,
                "quorum_mode": "for_and_abstain",
                "approval_mode": "for_strictly_exceeds_against",
                "approval_basis_points": 0,
                "declared_passed": False,
                "snapshot_complete": True,
            },
            {
                "proposal_id": "proposal-two",
                "snapshot_voting_power": 1_000,
                "for_votes": 100,
                "against_votes": 300,
                "abstain_votes": 100,
                "quorum_basis_points": 5_000,
                "quorum_mode": "all_votes",
                "approval_mode": "for_share_threshold",
                "approval_basis_points": 6_000,
                "declared_passed": False,
                "snapshot_complete": True,
            },
        ],
    }

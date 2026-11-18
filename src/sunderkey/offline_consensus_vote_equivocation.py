"""Group supplied validator votes with conflicting block identities."""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "consensus_supplied_conflicting_validator_votes"
PROFILE_ID = "AOE-GB-D10-S05"
CAPABILITY_ID = "army.gb.d10.s05"
VECTOR_ID = "AV-GB-D10-S05-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D10-S05"
WAVE_ID = "IW2-005"
COMMANDER_ID = "AOE-GB-D10-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:258a367c9b75fb7eeee715e10fec0c947d98459cb8aaaa39111cde38f42e42f6"
DOMAIN = "sunderkey.offline-consensus-vote-equivocation.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
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


class ConsensusVoteEquivocationError(ValueError):
    """A supplied vote ledger or original-model replay is invalid."""


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "context_complete", "votes"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise ConsensusVoteEquivocationError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["context_complete"], "context completeness")
    votes = core.bounded_list(model["votes"], 64, "votes")
    if not votes:
        raise ConsensusVoteEquivocationError("At least one vote is required")
    seen: set[str] = set()
    for item in votes:
        row = core.exact(
            item,
            {"vote_id", "validator_id", "chain_id", "height", "round", "step_id", "block_id"},
            "vote",
        )
        vote_id = core.identifier(row["vote_id"], "vote ID")
        if vote_id in seen:
            raise ConsensusVoteEquivocationError("Duplicate vote ID")
        seen.add(vote_id)
        for key in ("validator_id", "chain_id", "step_id", "block_id"):
            core.identifier(row[key], key)
        for key, ceiling in (("height", 1_000_000_000), ("round", 1_000_000)):
            count = row[key]
            if type(count) is not int or not 0 <= count <= ceiling:
                raise ConsensusVoteEquivocationError("Vote coordinates must be bounded integers")
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, model_text = _model(value)
    grouped: dict[tuple[str, str, int, int, str], dict[str, list[str]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for row in model["votes"]:
        key = (
            row["chain_id"],
            row["validator_id"],
            row["height"],
            row["round"],
            row["step_id"],
        )
        grouped[key][row["block_id"]].append(row["vote_id"])
    projections = []
    for key, blocks in sorted(grouped.items()):
        conflict = len(blocks) > 1
        disposition = (
            "unknown"
            if not model["context_complete"]
            else "candidate_declared_conflicting_validator_votes"
            if conflict
            else "no_declared_conflicting_validator_votes"
        )
        projections.append(
            {
                "chain_id": key[0],
                "validator_id": key[1],
                "height": key[2],
                "round": key[3],
                "step_id": key[4],
                "block_votes": [
                    {"block_id": block_id, "vote_ids": sorted(vote_ids)}
                    for block_id, vote_ids in sorted(blocks.items())
                ],
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
        "vote_count": len(model["votes"]),
        "coordinate_projections": projections,
        "candidate_count": sum(row["disposition"].startswith("candidate_") for row in projections),
        "unknown_count": sum(row["disposition"] == "unknown" for row in projections),
        "source_authenticated": False,
        "validator_signatures_verified": False,
        "consensus_rules_verified": False,
        "chain_queried": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Validator, chain, vote coordinates and block identities are caller-supplied.",
            "No signature, validator-set, consensus-step or chain-finality proof is checked.",
            "Conflicting labels do not prove signed equivocation or slashable conduct.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="CVE-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class ConsensusVoteEquivocationReport:
    """Unsigned vote projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise ConsensusVoteEquivocationError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> ConsensusVoteEquivocationReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_consensus_votes(model: Any) -> ConsensusVoteEquivocationReport:
    return ConsensusVoteEquivocationReport._owned(_derive(model))


def verify_supplied_consensus_votes(report: Any, *, model: Any) -> ConsensusVoteEquivocationReport:
    if type(report) is not ConsensusVoteEquivocationReport:
        raise ConsensusVoteEquivocationError("Exact consensus-vote wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise ConsensusVoteEquivocationError("Report differs from separate original model")
    return ConsensusVoteEquivocationReport._owned(expected)


def verify_supplied_consensus_votes_bytes(
    report_bytes: bytes, *, model: Any
) -> ConsensusVoteEquivocationReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise ConsensusVoteEquivocationError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise ConsensusVoteEquivocationError("Exported report differs from original replay")
    return ConsensusVoteEquivocationReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-validator-votes",
        "context_complete": True,
        "votes": [
            {
                "vote_id": "vote-one",
                "validator_id": "validator-a",
                "chain_id": "chain-a",
                "height": 10,
                "round": 0,
                "step_id": "commit",
                "block_id": "block-one",
            },
            {
                "vote_id": "vote-two",
                "validator_id": "validator-a",
                "chain_id": "chain-a",
                "height": 10,
                "round": 0,
                "step_id": "commit",
                "block_id": "block-two",
            },
        ],
    }

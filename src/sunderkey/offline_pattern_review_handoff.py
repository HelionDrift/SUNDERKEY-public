"""Prepare unsigned human review work from separately replayed pattern sources."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from . import offline_framework_declaration_core as core
from . import offline_pattern_claim_graph as graph
from . import offline_specialist_components as components

DOMAIN = "sunderkey.offline-pattern-review-handoff.v1"
MAX_REPORT_BYTES = 262_144
_FOLLOWUP = {
    "matches_declared_expectation": "challenge_source_scope_and_premise_semantics",
    "contradicts_declared_expectation": "resolve_declared_contradiction",
    "unresolved": "request_missing_or_ambiguous_evidence",
}
_EFFECTS = dict.fromkeys(
    ("authority", "credential", "deployment", "execution", "filesystem",
     "network", "process", "publication", "qualification", "target"),
    "none",
)


class PatternReviewHandoffError(ValueError):
    """Original graph, current catalog, or handoff derivation was rejected."""


def prepare_pattern_review_handoff(
    report: Any, *, model: Any, source_contexts: Any, catalog: Any,
    repository_root: str | Path,
) -> dict:
    """Replay graph sources and map typed premises to unaccepted review items."""
    try:
        current = graph.verify_supplied_pattern_claim_graph(
            report, model=model, source_contexts=source_contexts,
            catalog=catalog, repository_root=repository_root,
        ).to_dict()
        if type(catalog) is not components.OfflineSpecialistComponentCatalog:
            raise PatternReviewHandoffError("Exact current catalog required")
        checked_catalog = components.OfflineSpecialistComponentCatalog.from_dict(
            catalog.to_dict(), repository_root=repository_root,
        ).to_dict()
    except (
        graph.PatternClaimGraphError,
        components.OfflineSpecialistComponentError,
    ) as exc:
        raise PatternReviewHandoffError("Original/current graph or catalog failed") from exc

    descriptors = {row["component_id"]: row for row in checked_catalog["components"]}
    claim_items = []
    claim_owners: dict[str, dict] = {}
    for claim in current["claim_observations"]:
        descriptor = descriptors.get(claim["component_id"])
        if descriptor is None:
            raise PatternReviewHandoffError("Current catalog lacks premise owner")
        owner = {
            "profile_id": descriptor["profile_id"],
            "commander_profile_id": descriptor["commander_profile_id"],
            "independent_validator_id": descriptor["independent_validator_id"],
            "assignment_accepted": False,
            "review_accepted": False,
        }
        claim_owners[claim["claim_id"]] = owner
        claim_items.append(
            {
                "claim_id": claim["claim_id"],
                "scope_id": claim["scope_id"],
                "source_id": claim["source_id"],
                "premise_id": claim["observation_id"],
                "status": claim["status"],
                "requested_followup": _FOLLOWUP[claim["status"]],
                "ownership_reference": owner,
                "relation_analysis_sha256": claim["relation_analysis_sha256"],
                "task_result_sha256": claim["task_binding"]["task_result_sha256"],
                "leaf_analysis_sha256": claim["leaf_analysis_sha256"],
            }
        )

    by_hypothesis = {row["hypothesis_id"]: row for row in current["hypothesis_observations"]}
    contributors: dict[str, set[str]] = {}

    def collect(identifier: str) -> set[str]:
        if identifier not in contributors:
            selected: set[str] = set()
            for dependency in by_hypothesis[identifier]["dependencies"]:
                if dependency["kind"] == "claim":
                    selected.add(dependency["id"])
                else:
                    selected.update(collect(dependency["id"]))
            contributors[identifier] = selected
        return contributors[identifier]

    hypothesis_items = []
    for identifier in sorted(by_hypothesis):
        observed = by_hypothesis[identifier]
        selected = sorted(collect(identifier))
        owners = [claim_owners[item] for item in selected]
        hypothesis_items.append(
            {
                "hypothesis_id": identifier,
                "scope_id": observed["scope_id"],
                "status": observed["status"],
                "requested_followup": _FOLLOWUP[observed["status"]],
                "contributor_claim_ids": selected,
                "commander_profile_ids": sorted(
                    {owner["commander_profile_id"] for owner in owners}
                ),
                "independent_validator_ids": sorted(
                    {owner["independent_validator_id"] for owner in owners}
                ),
                "assignment_accepted": False,
                "review_accepted": False,
            }
        )

    body = {
        "schema_version": 1,
        "component_id": "supplied_pattern_review_handoff",
        "graph_analysis_id": current["analysis_id"],
        "graph_analysis_sha256": current["analysis_sha256"],
        "catalog_id": checked_catalog["catalog_id"],
        "catalog_sha256": checked_catalog["catalog_sha256"],
        "claim_review_items": claim_items,
        "hypothesis_review_items": hypothesis_items,
        "required_reviewer_roles": ["independent_control", "independent_assurance"],
        "review_status": "prepared_not_reviewed",
        "flags": {
            "source_authenticated": False,
            "shared_scope_proven": False,
            "independent_review_accepted": False,
            "full_candidate_assembled": False,
            "positive_use_approved": False,
            "qualification_claimed": False,
        },
        "operational_effects": dict(_EFFECTS),
        "limitations": [
            "Owner IDs are catalog references, not assignments or accepted reviews.",
            "Caller-declared scopes and supplied premises are not authenticated evidence.",
            "This handoff is for human challenge, not finding or action publication.",
            "Original pattern relations, tasks, and current catalog replay before use.",
        ],
    }
    analysis_id, analysis_sha256 = core.report_address(body, domain=DOMAIN, prefix="PRH-")
    packet = {**body, "analysis_id": analysis_id, "analysis_sha256": analysis_sha256}
    core.validate_tree(packet, maximum=MAX_REPORT_BYTES)
    return json.loads(core.canonical(packet))


def verify_pattern_review_handoff(
    packet: Any, *, report: Any, model: Any, source_contexts: Any, catalog: Any,
    repository_root: str | Path,
) -> dict:
    """Rebuild a packet from the graph and all separate current originals."""
    expected = prepare_pattern_review_handoff(
        report, model=model, source_contexts=source_contexts,
        catalog=catalog, repository_root=repository_root,
    )
    try:
        core.validate_tree(packet, maximum=MAX_REPORT_BYTES)
        supplied_json = core.canonical(packet)
    except (TypeError, ValueError) as exc:
        raise PatternReviewHandoffError("Invalid supplied review packet") from exc
    if type(packet) is not dict or supplied_json != core.canonical(expected):
        raise PatternReviewHandoffError("Review handoff differs from current original replay")
    return json.loads(supplied_json)

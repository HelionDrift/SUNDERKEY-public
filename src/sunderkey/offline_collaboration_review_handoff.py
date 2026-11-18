"""Prepare unsigned human review work from a replayed cross-task claim graph."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from . import offline_collaboration_claim_graph as graph
from . import offline_specialist_components as components

DOMAIN = "sunderkey.offline-collaboration-review-handoff.v1"
_FOLLOWUP = {
    "matches_declared_expectation": "challenge_source_scope_and_leaf_semantics",
    "contradicts_declared_expectation": "resolve_declared_contradiction",
    "unassessed": "request_missing_or_ambiguous_evidence",
}
_EFFECTS = dict.fromkeys(
    (
        "authority",
        "target",
        "network",
        "credential",
        "process",
        "execution",
        "routing",
        "qualification",
        "publication",
        "deployment",
        "assignment",
    ),
    "none",
)


class OfflineCollaborationReviewHandoffError(ValueError):
    """Current graph, catalog or review handoff integrity could not be established."""


def _digest(value: dict) -> str:
    encoded = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256((DOMAIN + "\n" + encoded).encode("ascii")).hexdigest()


def prepare_offline_collaboration_review_handoff(
    report: Any,
    *,
    model: Any,
    source_contexts: Any,
    catalog: Any,
    repository_root: str | Path,
) -> dict:
    """Replay separate originals and map supplied statuses to review questions."""
    try:
        current = graph.verify_offline_collaboration_claim_graph(
            report,
            model=model,
            source_contexts=source_contexts,
            catalog=catalog,
            repository_root=repository_root,
        )
        if type(catalog) is not components.OfflineSpecialistComponentCatalog:
            raise OfflineCollaborationReviewHandoffError("Exact current catalog required")
        checked_catalog = components.OfflineSpecialistComponentCatalog.from_dict(
            catalog.to_dict(), repository_root=repository_root
        ).to_dict()
    except (
        graph.OfflineCollaborationClaimGraphError,
        components.OfflineSpecialistComponentError,
    ) as exc:
        raise OfflineCollaborationReviewHandoffError(
            "Original/current graph or catalog verification failed"
        ) from exc
    descriptors = {row["component_id"]: row for row in checked_catalog["components"]}
    claim_items = []
    claim_owners: dict[str, dict | None] = {}
    for claim in current["claim_observations"]:
        component_id = claim["component_id"]
        descriptor = descriptors.get(component_id) if component_id is not None else None
        if component_id is not None and descriptor is None:
            raise OfflineCollaborationReviewHandoffError("Current catalog lacks claim owner")
        owner = (
            {
                "profile_id": descriptor["profile_id"],
                "commander_profile_id": descriptor["commander_profile_id"],
                "independent_validator_id": descriptor["independent_validator_id"],
                "assignment_accepted": False,
                "review_accepted": False,
            }
            if descriptor is not None
            else None
        )
        claim_owners[claim["claim_id"]] = owner
        claim_items.append(
            {
                "claim_id": claim["claim_id"],
                "scope_id": claim["scope_id"],
                "source_id": claim["source_id"],
                "observation_kind": claim["observation_kind"],
                "observation_id": claim["observation_id"],
                "status": claim["status"],
                "requested_followup": _FOLLOWUP[claim["status"]],
                "ownership_reference": owner,
                "relation_analysis_sha256": claim["relation_analysis_sha256"],
                "task_result_sha256": claim["task_binding"]["task_result_sha256"],
                "component_result_sha256": claim["component_result_sha256"],
                "leaf_analysis_sha256": claim["leaf_analysis_sha256"],
            }
        )
    by_hypothesis = {row["hypothesis_id"]: row for row in current["hypothesis_observations"]}
    contributors: dict[str, set[str]] = {}

    def collect(identifier: str) -> set[str]:
        if identifier in contributors:
            return contributors[identifier]
        selected: set[str] = set()
        for dependency in by_hypothesis[identifier]["dependencies"]:
            if dependency["kind"] == "claim":
                selected.add(dependency["id"])
            else:
                selected.update(collect(dependency["id"]))
        contributors[identifier] = selected
        return selected

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
                    {owner["commander_profile_id"] for owner in owners if owner is not None}
                ),
                "independent_validator_ids": sorted(
                    {owner["independent_validator_id"] for owner in owners if owner is not None}
                ),
                "ownership_incomplete": any(owner is None for owner in owners),
                "assignment_accepted": False,
                "review_accepted": False,
            }
        )
    body = {
        "schema_version": 1,
        "graph_id": current["graph_id"],
        "graph_sha256": current["graph_sha256"],
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
            "Caller-declared scopes and supplied decisions are not authenticated evidence.",
            "The packet is for human challenge, not finding or action publication.",
            "Original/current graph replay is required before every use.",
        ],
    }
    graph._capture(body, "review handoff")
    digest = _digest(body)
    return graph._capture(
        {
            **body,
            "handoff_id": "OCH-" + digest[7:39].upper(),
            "handoff_sha256": digest,
        },
        "review handoff",
    )[0]


def verify_offline_collaboration_review_handoff(
    packet: Any,
    *,
    report: Any,
    model: Any,
    source_contexts: Any,
    catalog: Any,
    repository_root: str | Path,
) -> dict:
    """Reject metadata substitution by rebuilding from current separate originals."""
    supplied, supplied_text = graph._capture(packet, "supplied review handoff")
    expected = prepare_offline_collaboration_review_handoff(
        report,
        model=model,
        source_contexts=source_contexts,
        catalog=catalog,
        repository_root=repository_root,
    )
    if supplied_text != graph._capture(expected, "expected review handoff")[1]:
        raise OfflineCollaborationReviewHandoffError(
            "Review handoff differs from current original derivation"
        )
    return supplied

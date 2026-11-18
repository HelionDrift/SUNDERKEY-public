"""Suppress challenged offline hypothesis edges without accepting unsigned review."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from . import attack_world_model as world
from . import offline_claim_world_projection as projection
from . import offline_collaboration_claim_graph as graph
from .offline_collaboration_review_custody import (
    OfflineCollaborationReviewCustodyError,
    OfflineCollaborationReviewCustodyStore,
)

DOMAIN = "sunderkey.offline-review-aware-world-projection.v1"
_SHA = re.compile(r"sha256:[0-9a-f]{64}\Z")
_ROLES = {"independent_control", "independent_assurance"}
_DISPOSITIONS = {None, "challenge", "needs_evidence", "accept_for_review_only"}
_STATES = {
    "contested_operator_assertion",
    "needs_evidence_operator_assertion",
    "dual_operator_assertions_unverified",
    "pending_operator_assertion",
}
_SUPPRESS = {"contested_operator_assertion", "needs_evidence_operator_assertion"}
_EFFECTS = dict.fromkeys(
    (
        "authority", "target", "network", "credential", "process", "execution",
        "routing", "qualification", "publication", "deployment", "assignment",
        "world_edge_promotion", "finding_transition",
    ),
    "none",
)


class OfflineReviewAwareWorldProjectionError(ValueError):
    """Source replay, custody join, or hypothesis-only filtering failed."""


def _sha(value: object, label: str) -> str:
    if type(value) is not str or _SHA.fullmatch(value) is None:
        raise OfflineReviewAwareWorldProjectionError(f"{label} is invalid")
    return value


def _exact(value: object, fields: set[str], label: str) -> dict:
    if type(value) is not dict or any(type(key) is not str for key in value):
        raise OfflineReviewAwareWorldProjectionError(f"{label} is invalid")
    if set(value) != fields:
        raise OfflineReviewAwareWorldProjectionError(f"{label} fields are invalid")
    return value


def _review_state(dispositions: dict) -> str:
    if "challenge" in dispositions.values():
        return "contested_operator_assertion"
    if "needs_evidence" in dispositions.values():
        return "needs_evidence_operator_assertion"
    if all(value == "accept_for_review_only" for value in dispositions.values()):
        return "dual_operator_assertions_unverified"
    return "pending_operator_assertion"


def _checked_states(
    summary: object, handoff: dict, *, tenant_id: str, scope_id: str
) -> dict[tuple[str, str], str]:
    summary = _exact(
        summary,
        {
            "schema_version", "tenant_id", "declared_scope_id", "handoff_sha256",
            "history_head_sequence", "history_head_sha256", "identity_assurance",
            "scope_assurance", "review_status", "item_review_states",
            "independent_review_accepted", "positive_use_approved", "operational_effects",
        },
        "current custody summary",
    )
    if (
        type(summary["schema_version"]) is not int
        or summary["schema_version"] != 1
        or summary["tenant_id"] != tenant_id
        or summary["declared_scope_id"] != scope_id
        or summary["handoff_sha256"] != handoff["handoff_sha256"]
        or type(summary["history_head_sequence"]) is not int
        or summary["history_head_sequence"] < 0
        or summary["identity_assurance"] != "operator_asserted_unsigned"
        or summary["scope_assurance"] != "caller_declared_unverified"
        or summary["review_status"] != "assertions_recorded_not_accepted"
        or summary["independent_review_accepted"] is not False
        or summary["positive_use_approved"] is not False
        or type(summary["operational_effects"]) is not dict
        or any(value != "none" for value in summary["operational_effects"].values())
    ):
        raise OfflineReviewAwareWorldProjectionError("current custody boundary is invalid")
    _sha(summary["history_head_sha256"], "custody head")
    expected = {
        (kind, item[key]): item
        for kind, field, key in (
            ("claim", "claim_review_items", "claim_id"),
            ("hypothesis", "hypothesis_review_items", "hypothesis_id"),
        )
        for item in handoff[field]
        if item["scope_id"] == scope_id
    }
    rows = summary["item_review_states"]
    if type(rows) is not list or len(rows) != len(expected):
        raise OfflineReviewAwareWorldProjectionError("current custody item set differs")
    states: dict[tuple[str, str], str] = {}
    for raw in rows:
        item = _exact(
            raw,
            {
                "item_kind", "item_id", "declared_scope_id", "source_status",
                "role_dispositions", "state",
            },
            "custody item state",
        )
        key = (item["item_kind"], item["item_id"])
        dispositions = _exact(item["role_dispositions"], _ROLES, "role dispositions")
        if (
            key not in expected
            or key in states
            or item["declared_scope_id"] != scope_id
            or item["source_status"] != expected[key]["status"]
            or any(type(value) is not str and value is not None for value in dispositions.values())
            or any(value not in _DISPOSITIONS for value in dispositions.values())
            or item["state"] not in _STATES
            or item["state"] != _review_state(dispositions)
        ):
            raise OfflineReviewAwareWorldProjectionError("custody item state differs")
        states[key] = item["state"]
    return states


def _derive(
    base: dict, handoff: dict, summary: dict, *, tenant_id: str, scope_id: str
) -> dict:
    if (
        base["graph_sha256"] != handoff["graph_sha256"]
        or base["source_model"]["scope_id"] != scope_id
        or summary["handoff_sha256"] != handoff["handoff_sha256"]
    ):
        raise OfflineReviewAwareWorldProjectionError("projection and review sources differ")
    states = _checked_states(summary, handoff, tenant_id=tenant_id, scope_id=scope_id)
    hypotheses = {
        item["hypothesis_id"]: item
        for item in handoff["hypothesis_review_items"]
        if item["scope_id"] == scope_id
    }
    links = {item["hypothesis_id"] for item in base["source_model"]["links"]}
    if set(hypotheses) != links:
        raise OfflineReviewAwareWorldProjectionError("hypothesis sets differ")
    original = world.AttackWorldSnapshot.from_dict(base["snapshot"])
    retained = []
    suppressed = []
    for edge in original.edges:
        if not edge.fact_id.startswith("declared:"):
            raise OfflineReviewAwareWorldProjectionError("unexpected world edge")
        hypothesis_id = edge.fact_id.removeprefix("declared:")
        if hypothesis_id not in hypotheses:
            raise OfflineReviewAwareWorldProjectionError("world edge has no hypothesis")
        item = hypotheses[hypothesis_id]
        blockers = []
        if states[("hypothesis", hypothesis_id)] in _SUPPRESS:
            blockers.append("hypothesis:" + hypothesis_id)
        for claim_id in item["contributor_claim_ids"]:
            if states.get(("claim", claim_id)) in _SUPPRESS:
                blockers.append("claim:" + claim_id)
        if blockers:
            suppressed.append({
                "hypothesis_id": hypothesis_id,
                "blocking_items": sorted(blockers),
                "reason": "unsigned_operator_challenge_or_missing_evidence",
            })
        else:
            retained.append(edge)
    filtered = world.build_attack_world_snapshot(original.nodes, retained)
    if any(
        fact.evidence.verification_state is not world.VerificationState.HYPOTHESIS
        or fact.evidence.confidence != 0.0
        for fact in (*filtered.nodes, *filtered.edges)
    ):
        raise OfflineReviewAwareWorldProjectionError("nonhypothetical world fact refused")
    body = {
        "schema_version": 1,
        "tenant_id": tenant_id,
        "declared_scope_id": scope_id,
        "base_projection_sha256": base["projection_sha256"],
        "graph_sha256": base["graph_sha256"],
        "handoff_sha256": handoff["handoff_sha256"],
        "custody_head_sequence": summary["history_head_sequence"],
        "custody_head_sha256": summary["history_head_sha256"],
        "snapshot": filtered.to_dict(),
        "base_withheld_links": base["withheld_links"],
        "review_suppressed_links": sorted(
            suppressed, key=lambda row: row["hypothesis_id"]
        ),
        "status": "review_filtered_hypotheses_only",
        "identity_assurance": "operator_asserted_unsigned",
        "scope_assurance": "caller_declared_unverified",
        "independent_review_accepted": False,
        "verified_path_created": False,
        "positive_use_approved": False,
        "operational_effects": dict(_EFFECTS),
    }
    projection._capture_report(body)
    digest = "sha256:" + hashlib.sha256(
        (DOMAIN + "\n" + json.dumps(
            body, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )).encode("ascii")
    ).hexdigest()
    return projection._capture_report({
        **body,
        "projection_id": "ORW-" + digest[7:39].upper(),
        "projection_sha256": digest,
    })[0]


def project_review_aware_world(
    base_projection: Any,
    *,
    projection_model: Any,
    graph_report: Any,
    graph_model: Any,
    source_contexts: Any,
    catalog: Any,
    repository_root: str | Path,
    handoff_packet: Any,
    review_store: OfflineCollaborationReviewCustodyStore,
    tenant_id: str,
) -> dict:
    """Replay current originals and only suppress challenged hypothesis edges."""
    if type(review_store) is not OfflineCollaborationReviewCustodyStore:
        raise OfflineReviewAwareWorldProjectionError("exact local review store is required")
    if type(tenant_id) is not str or tenant_id != review_store.tenant_id:
        raise OfflineReviewAwareWorldProjectionError("declared tenant differs from custody")
    try:
        handoff_copy = graph._capture(handoff_packet, "review handoff")[0]
        base = projection.verify_offline_claim_world_projection(
            base_projection,
            model=projection_model,
            report=graph_report,
            graph_model=graph_model,
            source_contexts=source_contexts,
            catalog=catalog,
            repository_root=repository_root,
        )
        summary = review_store.verify_current(
            packet=handoff_copy,
            report=graph_report,
            model=graph_model,
            source_contexts=source_contexts,
            catalog=catalog,
            repository_root=repository_root,
        )
        return _derive(
            base, handoff_copy, summary,
            tenant_id=tenant_id, scope_id=review_store.declared_scope_id,
        )
    except (
        graph.OfflineCollaborationClaimGraphError,
        projection.OfflineClaimWorldProjectionError,
        OfflineCollaborationReviewCustodyError,
        world.AttackWorldModelError,
        KeyError,
        TypeError,
    ) as exc:
        raise OfflineReviewAwareWorldProjectionError(
            "review-aware projection sources do not replay"
        ) from exc


def verify_review_aware_world(
    packet: Any, base_projection: Any, **sources: Any
) -> dict:
    """Rebuild the complete derivative against separate current originals."""
    supplied, supplied_text = projection._capture_report(packet)
    expected = project_review_aware_world(base_projection, **sources)
    if supplied_text != projection._capture_report(expected)[1]:
        raise OfflineReviewAwareWorldProjectionError(
            "review-aware projection differs from current originals"
        )
    return supplied


__all__ = [
    "OfflineReviewAwareWorldProjectionError",
    "project_review_aware_world",
    "verify_review_aware_world",
]

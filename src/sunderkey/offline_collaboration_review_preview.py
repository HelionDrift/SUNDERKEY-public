"""Build an internal metadata-only preview from a current review handoff."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from . import offline_collaboration_claim_graph as graph
from . import offline_collaboration_review_handoff as handoff

DOMAIN = "sunderkey.offline-collaboration-review-preview.v1"
_STATUSES = (
    "matches_declared_expectation",
    "contradicts_declared_expectation",
    "unassessed",
)
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


class OfflineCollaborationReviewPreviewError(ValueError):
    """The preview or an original/current replay could not be verified."""


def _digest(value: dict) -> str:
    encoded = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256((DOMAIN + "\n" + encoded).encode("ascii")).hexdigest()


def _status_counts(rows: list[dict]) -> dict[str, int]:
    return {status: sum(row["status"] == status for row in rows) for status in _STATUSES}


def prepare_offline_collaboration_review_preview(
    packet: Any,
    *,
    report: Any,
    model: Any,
    source_contexts: Any,
    catalog: Any,
    repository_root: str | Path,
) -> dict:
    """Replay the handoff, then publish only fixed metadata fields internally."""
    try:
        captured_report, _ = graph._capture(report, "review preview graph report")
        current = handoff.verify_offline_collaboration_review_handoff(
            packet,
            report=captured_report,
            model=model,
            source_contexts=source_contexts,
            catalog=catalog,
            repository_root=repository_root,
        )
    except (
        handoff.OfflineCollaborationReviewHandoffError,
        graph.OfflineCollaborationClaimGraphError,
    ) as exc:
        raise OfflineCollaborationReviewPreviewError(
            "Original/current review handoff replay failed"
        ) from exc
    claims = current["claim_review_items"]
    hypotheses = current["hypothesis_review_items"]
    owners = [row["ownership_reference"] for row in claims]
    known = [row for row in owners if row is not None]
    body = {
        "schema_version": 1,
        "graph_id": current["graph_id"],
        "graph_sha256": current["graph_sha256"],
        "handoff_id": current["handoff_id"],
        "handoff_sha256": current["handoff_sha256"],
        "catalog_id": current["catalog_id"],
        "catalog_sha256": current["catalog_sha256"],
        "source_count": len(captured_report["source_bindings"]),
        "claim_count": len(claims),
        "hypothesis_count": len(hypotheses),
        "claim_status_counts": _status_counts(claims),
        "hypothesis_status_counts": _status_counts(hypotheses),
        "ownership_status_counts": {
            "catalog_reference_present": len(known),
            "catalog_reference_absent": len(owners) - len(known),
            "hypothesis_ownership_incomplete": sum(
                row["ownership_incomplete"] for row in hypotheses
            ),
        },
        "catalog_profile_ids": {
            "specialist": sorted({row["profile_id"] for row in known}),
            "commander": sorted({row["commander_profile_id"] for row in known}),
            "independent_validator": sorted(
                {row["independent_validator_id"] for row in known}
            ),
        },
        "required_reviewer_roles": list(current["required_reviewer_roles"]),
        "review_status": "internal_preview_not_reviewed",
        "qualification_effect": "none",
        "customer_publication_approved": False,
        "operational_effects": dict(_EFFECTS),
    }
    graph._capture(body, "review preview")
    address = _digest(body)
    return graph._capture(
        {
            **body,
            "preview_id": "OCP-" + address[7:39].upper(),
            "preview_sha256": address,
        },
        "review preview",
    )[0]


def verify_offline_collaboration_review_preview(
    preview: Any,
    *,
    packet: Any,
    report: Any,
    model: Any,
    source_contexts: Any,
    catalog: Any,
    repository_root: str | Path,
) -> dict:
    """Compare exact native preview bytes to a fresh separate-source derivation."""
    try:
        supplied, supplied_text = graph._capture(preview, "supplied review preview")
        expected = prepare_offline_collaboration_review_preview(
            packet,
            report=report,
            model=model,
            source_contexts=source_contexts,
            catalog=catalog,
            repository_root=repository_root,
        )
        if supplied_text != graph._capture(expected, "expected review preview")[1]:
            raise OfflineCollaborationReviewPreviewError(
                "Preview differs from current original derivation"
            )
    except graph.OfflineCollaborationClaimGraphError as exc:
        raise OfflineCollaborationReviewPreviewError("Invalid bounded preview") from exc
    return supplied

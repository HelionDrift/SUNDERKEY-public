"""Unsigned comparison of independently replayed collaboration hypotheses."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from . import offline_collaboration_claim_graph as graph

DOMAIN = "sunderkey.offline-collaboration-claim-delta.v1"
MAX_PAIRS = 16
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


class OfflineCollaborationClaimDeltaError(ValueError):
    """A declaration or separately replayed graph source was refused."""


def _capture(value: Any, label: str) -> tuple[Any, str]:
    try:
        return graph._capture(value, label)
    except graph.OfflineCollaborationClaimGraphError as exc:
        raise OfflineCollaborationClaimDeltaError(f"{label} is not bounded native JSON") from exc


def _fields(value: Any, names: set[str], label: str) -> None:
    if type(value) is not dict or value.keys() != names:
        raise OfflineCollaborationClaimDeltaError(f"{label} fields are invalid")


def _identifier(value: Any, label: str) -> None:
    try:
        graph._identifier(value, label)
    except graph.OfflineCollaborationClaimGraphError as exc:
        raise OfflineCollaborationClaimDeltaError(f"{label} identifier is invalid") from exc


def _plan(model: Any) -> dict:
    plan = _capture(model, "claim delta model")[0]
    _fields(plan, {"schema_version", "comparison_label", "sources", "pairs"}, "delta model")
    if type(plan["schema_version"]) is not int or plan["schema_version"] != 1:
        raise OfflineCollaborationClaimDeltaError("Delta schema version is invalid")
    _identifier(plan["comparison_label"], "comparison")
    sources = plan["sources"]
    if type(sources) is not list or len(sources) != 2:
        raise OfflineCollaborationClaimDeltaError("Exactly two graph sources required")
    source_ids = set()
    for source in sources:
        _fields(source, {"source_id"}, "graph source")
        _identifier(source["source_id"], "graph source")
        source_ids.add(source["source_id"])
    if len(source_ids) != 2:
        raise OfflineCollaborationClaimDeltaError("Distinct graph source labels required")
    pairs = plan["pairs"]
    if type(pairs) is not list or not 1 <= len(pairs) <= MAX_PAIRS:
        raise OfflineCollaborationClaimDeltaError("Claim pair limit exceeded")
    pair_ids: set[str] = set()
    for pair in pairs:
        _fields(pair, {"pair_id", "subject_id", "basis", "before", "after"}, "claim pair")
        _identifier(pair["pair_id"], "pair")
        _identifier(pair["subject_id"], "declared subject")
        if pair["basis"] != "caller_declared_unverified":
            raise OfflineCollaborationClaimDeltaError("Subject binding must be explicit")
        if pair["pair_id"] in pair_ids:
            raise OfflineCollaborationClaimDeltaError("Duplicate claim pair identifier")
        pair_ids.add(pair["pair_id"])
        for side in ("before", "after"):
            reference = pair[side]
            _fields(reference, {"source_id", "hypothesis_id"}, side)
            _identifier(reference["source_id"], side + " source")
            _identifier(reference["hypothesis_id"], side + " hypothesis")
        if (
            pair["before"]["source_id"] not in source_ids
            or pair["after"]["source_id"] not in source_ids
            or pair["before"]["source_id"] == pair["after"]["source_id"]
        ):
            raise OfflineCollaborationClaimDeltaError("Pair must cross exact two graphs")
    return plan


def _digest(body: dict) -> str:
    encoded = json.dumps(body, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256((DOMAIN + "\n" + encoded).encode("ascii")).hexdigest()


def analyze_offline_collaboration_claim_delta(
    model: Any, *, graph_contexts: Any, catalog: Any, repository_root: str | Path
) -> dict:
    """Compare supplied hypothesis statuses without target or chronology claims."""
    plan = _plan(model)
    source_ids = {row["source_id"] for row in plan["sources"]}
    if type(graph_contexts) is not dict or graph_contexts.keys() != source_ids:
        raise OfflineCollaborationClaimDeltaError("Exact separate graph contexts required")
    reports = {}
    for source_id in sorted(source_ids):
        context = graph_contexts[source_id]
        _fields(context, {"graph_report", "graph_model", "source_contexts"}, "graph context")
        try:
            reports[source_id] = graph.verify_offline_collaboration_claim_graph(
                context["graph_report"],
                model=context["graph_model"],
                source_contexts=context["source_contexts"],
                catalog=catalog,
                repository_root=repository_root,
            )
        except graph.OfflineCollaborationClaimGraphError as exc:
            raise OfflineCollaborationClaimDeltaError(
                f"Graph {source_id} original/current replay failed"
            ) from exc
    evidence_sets = [
        tuple(
            sorted(
                (
                    row["analysis_sha256"],
                    row["task_binding"]["task_result_sha256"],
                )
                for row in report["source_bindings"]
            )
        )
        for report in reports.values()
    ]
    if evidence_sets[0] == evidence_sets[1]:
        raise OfflineCollaborationClaimDeltaError("Repeated graph evidence is not a delta")
    observations = []
    for pair in sorted(plan["pairs"], key=lambda row: row["pair_id"]):
        selected = []
        for side in ("before", "after"):
            reference = pair[side]
            source_id = reference["source_id"]
            report = reports[source_id]
            rows = [
                row
                for row in report["hypothesis_observations"]
                if row["hypothesis_id"] == reference["hypothesis_id"]
            ]
            if len(rows) != 1:
                raise OfflineCollaborationClaimDeltaError("Pair lacks one typed hypothesis")
            row = rows[0]
            selected.append(
                {
                    "source_id": source_id,
                    "hypothesis_id": row["hypothesis_id"],
                    "declared_scope_id": row["scope_id"],
                    "status": row["status"],
                    "dependencies": row["dependencies"],
                    "graph_sha256": report["graph_sha256"],
                }
            )
        before, after = selected
        if "unassessed" in (before["status"], after["status"]):
            state = "unassessed"
        elif before["status"] == after["status"]:
            state = "same_declared_status"
        else:
            state = "changed_declared_status"
        observations.append(
            {
                "pair_id": pair["pair_id"],
                "subject_id": pair["subject_id"],
                "binding_basis": pair["basis"],
                "before": before,
                "after": after,
                "state": state,
            }
        )
    body = {
        "schema_version": 1,
        "source_model": plan,
        "source_bindings": [
            {
                "source_id": source_id,
                "graph_id": reports[source_id]["graph_id"],
                "graph_sha256": reports[source_id]["graph_sha256"],
                "source_bindings": reports[source_id]["source_bindings"],
            }
            for source_id in sorted(source_ids)
        ],
        "pair_observations": observations,
        "flags": {
            "source_authenticated": False,
            "subject_equivalence_proven": False,
            "scope_equivalence_proven": False,
            "time_order_proven": False,
            "improvement_claimed": False,
            "regression_claimed": False,
            "finding_claimed": False,
            "positive_use_approved": False,
            "qualification_claimed": False,
        },
        "operational_effects": dict(_EFFECTS),
        "limitations": [
            "Before and after are caller labels, not independently established chronology.",
            "Equal subject or scope labels do not prove a shared target, tenant or identity.",
            "Status differences can reflect changed dependency definitions or supplied data.",
            "No status delta is an improvement, regression, finding or authority.",
        ],
    }
    _capture(body, "claim delta report")
    digest = _digest(body)
    return _capture(
        {**body, "delta_id": "OCD-" + digest[7:39].upper(), "delta_sha256": digest},
        "claim delta report",
    )[0]


def verify_offline_collaboration_claim_delta(
    report: Any,
    *,
    model: Any,
    graph_contexts: Any,
    catalog: Any,
    repository_root: str | Path,
) -> dict:
    """Rebuild from both current original graphs, not an untrusted digest."""
    supplied, text = _capture(report, "supplied claim delta")
    expected = analyze_offline_collaboration_claim_delta(
        model, graph_contexts=graph_contexts, catalog=catalog, repository_root=repository_root
    )
    if text != _capture(expected, "expected claim delta")[1]:
        raise OfflineCollaborationClaimDeltaError("Delta differs from original/current derivation")
    return supplied

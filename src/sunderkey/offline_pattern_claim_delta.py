"""Compare separately replayed pattern hypotheses without target claims."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from . import offline_collaboration_claim_delta as grammar
from . import offline_framework_declaration_core as core
from . import offline_pattern_claim_graph as graph

DOMAIN = "sunderkey.offline-pattern-claim-delta.v1"
MAX_REPORT_BYTES = 262_144
_EFFECTS = dict.fromkeys(
    ("authority", "credential", "deployment", "execution", "filesystem",
     "network", "process", "publication", "qualification", "target"),
    "none",
)
_FLAGS = {
    "source_authenticated": False,
    "subject_equivalence_proven": False,
    "scope_equivalence_proven": False,
    "time_order_proven": False,
    "improvement_claimed": False,
    "regression_claimed": False,
    "finding_claimed": False,
    "positive_use_approved": False,
    "qualification_claimed": False,
}


class PatternClaimDeltaError(ValueError):
    """A comparison declaration or separately replayed graph was rejected."""


def _plan(value: Any) -> dict:
    try:
        return grammar._plan(value)
    except grammar.OfflineCollaborationClaimDeltaError as exc:
        raise PatternClaimDeltaError("Comparison declaration is invalid") from exc


def analyze_pattern_claim_delta(
    model: Any, *, graph_contexts: Any, catalog: Any, repository_root: str | Path,
) -> dict:
    """Compare declared hypothesis statuses, never target or time equivalence."""
    plan = _plan(model)
    source_ids = {row["source_id"] for row in plan["sources"]}
    if type(graph_contexts) is not dict or set(graph_contexts) != source_ids:
        raise PatternClaimDeltaError("Exact separate graph contexts required")
    if len({id(context) for context in graph_contexts.values()}) != len(graph_contexts):
        raise PatternClaimDeltaError("Graph comparison requires distinct context objects")
    reports: dict[str, dict] = {}
    for source_id in sorted(source_ids):
        context = graph_contexts[source_id]
        if type(context) is not dict or set(context) != {
            "graph_report", "graph_model", "source_contexts"
        }:
            raise PatternClaimDeltaError("Exact original graph context required")
        try:
            reports[source_id] = graph.verify_supplied_pattern_claim_graph(
                context["graph_report"], model=context["graph_model"],
                source_contexts=context["source_contexts"], catalog=catalog,
                repository_root=repository_root,
            ).to_dict()
        except graph.PatternClaimGraphError as exc:
            raise PatternClaimDeltaError(
                f"Graph {source_id} original/current replay failed"
            ) from exc
    evidence_sets = [
        tuple(sorted(
            row["task_binding"]["task_result_sha256"]
            for row in report["source_bindings"]
        ))
        for report in reports.values()
    ]
    if evidence_sets[0] == evidence_sets[1]:
        raise PatternClaimDeltaError("Repeated task evidence is not a graph delta")

    observations = []
    for pair in sorted(plan["pairs"], key=lambda row: row["pair_id"]):
        selected = []
        for side in ("before", "after"):
            reference = pair[side]
            report = reports[reference["source_id"]]
            rows = [
                row for row in report["hypothesis_observations"]
                if row["hypothesis_id"] == reference["hypothesis_id"]
            ]
            if len(rows) != 1:
                raise PatternClaimDeltaError("Pair lacks one typed hypothesis")
            row = rows[0]
            selected.append(
                {
                    "source_id": reference["source_id"],
                    "hypothesis_id": row["hypothesis_id"],
                    "declared_scope_id": row["scope_id"],
                    "status": row["status"],
                    "dependencies": row["dependencies"],
                    "graph_analysis_sha256": report["analysis_sha256"],
                }
            )
        before, after = selected
        if "unresolved" in (before["status"], after["status"]):
            state = "unresolved"
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
        "component_id": "supplied_pattern_claim_delta",
        "source_model": plan,
        "source_bindings": [
            {
                "source_id": source_id,
                "graph_analysis_id": reports[source_id]["analysis_id"],
                "graph_analysis_sha256": reports[source_id]["analysis_sha256"],
                "source_bindings": reports[source_id]["source_bindings"],
            }
            for source_id in sorted(source_ids)
        ],
        "pair_observations": observations,
        "flags": dict(_FLAGS),
        "operational_effects": dict(_EFFECTS),
        "limitations": [
            "Before and after are caller labels, not established chronology.",
            "Equal subject or scope labels do not prove a shared target or identity.",
            "Changed statuses can reflect changed definitions or supplied data.",
            "No status delta is an improvement, regression, finding or authority.",
        ],
    }
    analysis_id, analysis_sha256 = core.report_address(body, domain=DOMAIN, prefix="PCD-")
    result = {**body, "analysis_id": analysis_id, "analysis_sha256": analysis_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return json.loads(core.canonical(result))


def verify_pattern_claim_delta(
    report: Any, *, model: Any, graph_contexts: Any, catalog: Any,
    repository_root: str | Path,
) -> dict:
    """Rebuild a comparison from both graph sources and current originals."""
    try:
        core.validate_tree(report, maximum=MAX_REPORT_BYTES)
        supplied_json = core.canonical(report)
    except (TypeError, ValueError) as exc:
        raise PatternClaimDeltaError("Invalid supplied comparison") from exc
    if type(report) is not dict:
        raise PatternClaimDeltaError("Invalid supplied comparison")
    if report.get("flags") != _FLAGS or report.get("operational_effects") != _EFFECTS:
        raise PatternClaimDeltaError("Comparison claims effects outside the offline boundary")
    expected = analyze_pattern_claim_delta(
        model, graph_contexts=graph_contexts, catalog=catalog,
        repository_root=repository_root,
    )
    if supplied_json != core.canonical(expected):
        raise PatternClaimDeltaError("Comparison differs from current original replay")
    return json.loads(supplied_json)

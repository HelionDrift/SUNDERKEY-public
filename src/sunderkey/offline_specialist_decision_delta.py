"""Unsigned semantic deltas over separately replayed supplied-flow decisions."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from . import offline_collaboration_claim_graph as graph
from . import offline_specialist_task_relations as relations

DOMAIN = "sunderkey.offline-specialist-decision-delta.v1"
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


class OfflineSpecialistDecisionDeltaError(ValueError):
    """A typed declaration, original source, or current replay was refused."""


def _fields(value: Any, expected: set[str], label: str) -> None:
    if type(value) is not dict or value.keys() != expected:
        raise OfflineSpecialistDecisionDeltaError(f"{label} fields are invalid")


def _identifier(value: Any, label: str) -> None:
    try:
        graph._identifier(value, label)
    except graph.OfflineCollaborationClaimGraphError as exc:
        raise OfflineSpecialistDecisionDeltaError(f"{label} identifier is invalid") from exc


def _plan(model: Any) -> dict:
    try:
        plan = graph._capture(model, "decision delta model")[0]
    except graph.OfflineCollaborationClaimGraphError as exc:
        raise OfflineSpecialistDecisionDeltaError(
            "Decision delta model is not bounded native JSON"
        ) from exc
    _fields(plan, {"schema_version", "comparison_label", "sources", "pairs"}, "delta model")
    if type(plan["schema_version"]) is not int or plan["schema_version"] != 1:
        raise OfflineSpecialistDecisionDeltaError("Delta schema version is invalid")
    _identifier(plan["comparison_label"], "comparison")
    if type(plan["sources"]) is not list or len(plan["sources"]) != 2:
        raise OfflineSpecialistDecisionDeltaError("Exactly two separate sources required")
    source_ids = set()
    for source in plan["sources"]:
        _fields(source, {"source_id"}, "delta source")
        _identifier(source["source_id"], "source")
        source_ids.add(source["source_id"])
    if len(source_ids) != 2:
        raise OfflineSpecialistDecisionDeltaError("Distinct source labels required")
    pairs = plan["pairs"]
    if type(pairs) is not list or not 1 <= len(pairs) <= MAX_PAIRS:
        raise OfflineSpecialistDecisionDeltaError("Decision pair limit exceeded")
    pair_ids: set[str] = set()
    for pair in pairs:
        _fields(pair, {"pair_id", "subject_id", "basis", "before", "after"}, "pair")
        _identifier(pair["pair_id"], "pair")
        _identifier(pair["subject_id"], "declared subject")
        if pair["basis"] != "caller_declared_unverified":
            raise OfflineSpecialistDecisionDeltaError("Subject binding must be explicit")
        if pair["pair_id"] in pair_ids:
            raise OfflineSpecialistDecisionDeltaError("Duplicate pair identifier")
        pair_ids.add(pair["pair_id"])
        for side in ("before", "after"):
            ref = pair[side]
            _fields(ref, {"source_id", "premise_id"}, side)
            _identifier(ref["source_id"], side + " source")
            _identifier(ref["premise_id"], side + " premise")
        if (
            pair["before"]["source_id"] not in source_ids
            or pair["after"]["source_id"] not in source_ids
            or pair["before"]["source_id"] == pair["after"]["source_id"]
        ):
            raise OfflineSpecialistDecisionDeltaError("Pair must cross exact two sources")
    return plan


def _digest(body: dict) -> str:
    encoded = json.dumps(body, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256((DOMAIN + "\n" + encoded).encode("ascii")).hexdigest()


def analyze_offline_specialist_decision_delta(
    model: Any, *, source_contexts: Any, catalog: Any, repository_root: str | Path
) -> dict:
    """Compare actual supplied decisions, never improvement or live state."""
    plan = _plan(model)
    source_ids = {row["source_id"] for row in plan["sources"]}
    if type(source_contexts) is not dict or source_contexts.keys() != source_ids:
        raise OfflineSpecialistDecisionDeltaError("Exact separate source contexts required")
    for context in source_contexts.values():
        _fields(
            context,
            {"relation_report", "relation_model", "task_report", "task_model"},
            "source context",
        )
        if type(context["relation_report"]) is not relations.OfflineSpecialistTaskRelations:
            raise OfflineSpecialistDecisionDeltaError("Exact native relation report required")
    reports = {}
    for source_id in sorted(source_ids):
        context = source_contexts[source_id]
        try:
            checked = relations.verify_offline_specialist_task_relations(
                context["relation_report"],
                model=context["relation_model"],
                task_report=context["task_report"],
                task_model=context["task_model"],
                catalog=catalog,
                repository_root=repository_root,
            )
            reports[source_id] = checked.to_dict()
        except relations.OfflineSpecialistTaskRelationsError as exc:
            raise OfflineSpecialistDecisionDeltaError(
                f"Source {source_id} original/current replay failed"
            ) from exc
    addresses = [row["task_binding"]["task_result_sha256"] for row in reports.values()]
    if len(set(addresses)) != 2:
        raise OfflineSpecialistDecisionDeltaError("Repeated task evidence cannot be a delta")
    items = []
    for pair in sorted(plan["pairs"], key=lambda row: row["pair_id"]):
        selected = []
        for side in ("before", "after"):
            source_id = pair[side]["source_id"]
            report = reports[source_id]
            rows = [
                row
                for row in report["premise_observations"]
                if row["premise_id"] == pair[side]["premise_id"]
            ]
            if len(rows) != 1:
                raise OfflineSpecialistDecisionDeltaError("Pair lacks one typed premise")
            row = rows[0]
            selected.append(
                {
                    "source_id": source_id,
                    "premise_id": row["premise_id"],
                    "component_id": row["component_id"],
                    "flow_id": row["flow_id"],
                    "actual_decision": row["actual_decision"],
                    "expected_decision": row["expected_decision"],
                    "relation_analysis_sha256": report["analysis_sha256"],
                    "task_result_sha256": report["task_binding"]["task_result_sha256"],
                    "component_result_sha256": row["component_result_sha256"],
                    "leaf_analysis_sha256": row["leaf_analysis_sha256"],
                }
            )
        before, after = selected
        if before["component_id"] != after["component_id"]:
            raise OfflineSpecialistDecisionDeltaError("Cross-component decision comparison refused")
        if "unassessed" in (before["actual_decision"], after["actual_decision"]):
            state = "unassessed"
        elif before["actual_decision"] == after["actual_decision"]:
            state = "same_supplied_decision"
        else:
            state = "changed_supplied_decision"
        items.append(
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
                "analysis_id": reports[source_id]["analysis_id"],
                "analysis_sha256": reports[source_id]["analysis_sha256"],
                "task_binding": reports[source_id]["task_binding"],
            }
            for source_id in sorted(source_ids)
        ],
        "pair_observations": items,
        "flags": {
            "source_authenticated": False,
            "subject_equivalence_proven": False,
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
            "Equal subject labels do not prove shared target, tenant, flow or identity.",
            "Supplied decisions are partial provider predicates, not observed reachability.",
            "A changed decision is not improvement, regression, finding or authority.",
        ],
    }
    try:
        graph._capture(body, "decision delta report")
        digest = _digest(body)
        return graph._capture(
            {
                **body,
                "delta_id": "OSD-" + digest[7:39].upper(),
                "delta_sha256": digest,
            },
            "decision delta report",
        )[0]
    except graph.OfflineCollaborationClaimGraphError as exc:
        raise OfflineSpecialistDecisionDeltaError("Decision delta output limit exceeded") from exc


def verify_offline_specialist_decision_delta(
    report: Any,
    *,
    model: Any,
    source_contexts: Any,
    catalog: Any,
    repository_root: str | Path,
) -> dict:
    """Rebuild from current separate originals, not just a report digest."""
    try:
        supplied, text = graph._capture(report, "supplied decision delta")
    except graph.OfflineCollaborationClaimGraphError as exc:
        raise OfflineSpecialistDecisionDeltaError(
            "Supplied delta is not bounded native JSON"
        ) from exc
    expected = analyze_offline_specialist_decision_delta(
        model,
        source_contexts=source_contexts,
        catalog=catalog,
        repository_root=repository_root,
    )
    if text != graph._capture(expected, "expected decision delta")[1]:
        raise OfflineSpecialistDecisionDeltaError("Delta differs from original/current derivation")
    return supplied

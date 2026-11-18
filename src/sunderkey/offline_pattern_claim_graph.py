"""Compose separate current-source pattern relations under unverified scopes."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import offline_collaboration_claim_graph as grammar
from . import offline_framework_declaration_core as core
from . import offline_pattern_task_relations as pattern

COMPONENT_ID = "supplied_pattern_claim_graph"
DOMAIN = "sunderkey.offline-pattern-claim-graph.v1"
MAX_REPORT_BYTES = 262_144
_MATCH = "matches_declared_expectation"
_CONTRARY = "contradicts_declared_expectation"
_UNKNOWN = "unresolved"
_STATUSES = {_MATCH, _CONTRARY, _UNKNOWN}
_EFFECTS = dict.fromkeys(
    ("authority", "credential", "deployment", "execution", "filesystem",
     "network", "process", "publication", "qualification", "target"),
    "none",
)
_FLAGS = {
    "offline_only": True,
    "scope_equivalence_proven": False,
    "source_authenticated": False,
    "full_candidate_assembled": False,
    "positive_use_approved": False,
    "qualification_claimed": False,
}


class PatternClaimGraphError(ValueError):
    """A closed graph, separate source, or current replay was rejected."""


def _plan(value: Any) -> dict:
    try:
        plan = grammar._plan(value)
    except grammar.OfflineCollaborationClaimGraphError as exc:
        raise PatternClaimGraphError("Graph declaration is invalid") from exc
    if any(row["observation_kind"] != "premise" for row in plan["claims"]):
        raise PatternClaimGraphError("Pattern claims select only source premises")
    return plan


def _derive(
    model: Any, *, source_contexts: Any, catalog: Any, repository_root: str | Path,
) -> dict:
    plan = _plan(model)
    source_ids = {row["source_id"] for row in plan["sources"]}
    if type(source_contexts) is not dict or set(source_contexts) != source_ids:
        raise PatternClaimGraphError("Exact separate source contexts are required")
    if len({id(context) for context in source_contexts.values()}) != len(source_contexts):
        raise PatternClaimGraphError("Graph sources must be distinct context objects")
    for source_id, context in source_contexts.items():
        if (
            type(source_id) is not str
            or type(context) is not dict
            or set(context) != {"relation_report", "relation_model", "task_report", "task_model"}
            or type(context["relation_report"]) is not pattern.PatternTaskRelations
        ):
            raise PatternClaimGraphError("Exact original relation context is required")
    verified: dict[str, dict] = {}
    for source_id in sorted(source_ids):
        context = source_contexts[source_id]
        try:
            verified[source_id] = pattern.verify_supplied_pattern_task_relations(
                context["relation_report"], model=context["relation_model"],
                task_report=context["task_report"], task_model=context["task_model"],
                catalog=catalog, repository_root=repository_root,
            ).to_dict()
        except pattern.PatternTaskRelationsError as exc:
            raise PatternClaimGraphError(
                f"Source {source_id} original/current replay failed"
            ) from exc
    task_addresses = [
        row["task_binding"]["task_result_sha256"] for row in verified.values()
    ]
    if len(set(task_addresses)) != len(task_addresses):
        raise PatternClaimGraphError(
            "Repeated task evidence cannot masquerade as distinct graph sources"
        )
    claims = []
    statuses: dict[tuple[str, str], str] = {}
    for claim in sorted(plan["claims"], key=lambda row: row["claim_id"]):
        source = verified[claim["source_id"]]
        selected = [
            row for row in source["premises"]
            if row["premise_id"] == claim["observation_id"]
        ]
        if len(selected) != 1 or selected[0]["status"] not in _STATUSES:
            raise PatternClaimGraphError("Claim selector lacks one typed premise")
        premise = selected[0]
        claims.append(
            {
                **claim,
                "status": premise["status"],
                "relation_analysis_id": source["analysis_id"],
                "relation_analysis_sha256": source["analysis_sha256"],
                "task_binding": source["task_binding"],
                "component_id": premise["component_id"],
                "leaf_analysis_sha256": premise["leaf_analysis_sha256"],
            }
        )
        statuses[("claim", claim["claim_id"])] = premise["status"]
    by_hypothesis = {row["hypothesis_id"]: row for row in plan["hypotheses"]}
    derived: dict[str, dict] = {}

    def evaluate(identifier: str) -> None:
        if identifier in derived:
            return
        hypothesis = by_hypothesis[identifier]
        dependencies = []
        for reference in sorted(
            hypothesis["dependencies"], key=lambda row: (row["kind"], row["id"])
        ):
            if reference["kind"] == "hypothesis":
                evaluate(reference["id"])
            dependencies.append(
                {**reference, "status": statuses[(reference["kind"], reference["id"])]}
            )
        values = {row["status"] for row in dependencies}
        status = _CONTRARY if _CONTRARY in values else (_UNKNOWN if _UNKNOWN in values else _MATCH)
        derived[identifier] = {
            "hypothesis_id": identifier,
            "scope_id": hypothesis["scope_id"],
            "dependencies": dependencies,
            "status": status,
        }
        statuses[("hypothesis", identifier)] = status

    for identifier in sorted(by_hypothesis):
        evaluate(identifier)
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "source_model": plan,
        "source_bindings": [
            {
                "source_id": source_id,
                "analysis_id": verified[source_id]["analysis_id"],
                "analysis_sha256": verified[source_id]["analysis_sha256"],
                "task_binding": verified[source_id]["task_binding"],
            }
            for source_id in sorted(source_ids)
        ],
        "claim_observations": claims,
        "hypothesis_observations": [derived[key] for key in sorted(derived)],
        "flags": dict(_FLAGS),
        "operational_effects": dict(_EFFECTS),
        "limitations": [
            "Scope links are declarations, not proof of shared target, tenant, or identity.",
            "Source premises are partial supplied observations, not findings or pathways.",
            "Each original relation and task plus the current catalog is required for use.",
            "No target action, publication, authorization, or qualification follows.",
        ],
    }
    analysis_id, analysis_sha256 = core.report_address(body, domain=DOMAIN, prefix="PCG-")
    report = {**body, "analysis_id": analysis_id, "analysis_sha256": analysis_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return json.loads(core.canonical(report))


@dataclass(frozen=True, slots=True, init=False)
class PatternClaimGraph:
    """Unsigned graph requiring separate source replay for verification."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise PatternClaimGraphError("Use analysis or source-replaying verification")

    @classmethod
    def _owned(cls, document: dict) -> PatternClaimGraph:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_pattern_claim_graph(
    model: Any, *, source_contexts: Any, catalog: Any, repository_root: str | Path,
) -> PatternClaimGraph:
    return PatternClaimGraph._owned(
        _derive(
            model, source_contexts=source_contexts, catalog=catalog,
            repository_root=repository_root,
        )
    )


def verify_supplied_pattern_claim_graph(
    report: Any, *, model: Any, source_contexts: Any, catalog: Any,
    repository_root: str | Path,
) -> PatternClaimGraph:
    if type(report) is not PatternClaimGraph:
        raise PatternClaimGraphError("Exact native graph wrapper required")
    try:
        supplied = report.to_dict()
    except (TypeError, ValueError) as exc:
        raise PatternClaimGraphError("Graph wrapper is invalid") from exc
    if type(supplied) is not dict or (
        supplied.get("flags") != _FLAGS
        or supplied.get("operational_effects") != _EFFECTS
    ):
        raise PatternClaimGraphError("Graph claims effects outside the offline boundary")
    expected = _derive(
        model, source_contexts=source_contexts, catalog=catalog,
        repository_root=repository_root,
    )
    if report.to_json() != core.canonical(expected):
        raise PatternClaimGraphError("Graph differs from separate original replay")
    return PatternClaimGraph._owned(expected)


def verify_supplied_pattern_claim_graph_bytes(
    report_bytes: bytes, *, model: Any, source_contexts: Any, catalog: Any,
    repository_root: str | Path,
) -> PatternClaimGraph:
    """Verify an exported graph against separate originals and current sources."""
    try:
        report = pattern._parse_document(
            report_bytes, maximum=MAX_REPORT_BYTES, label="Graph report",
        )
        core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    except (pattern.PatternTaskRelationsError, core.FrameworkDeclarationError) as exc:
        raise PatternClaimGraphError("Exported graph report is invalid") from exc
    if type(report) is not dict:
        raise PatternClaimGraphError("Exported graph report must be an object")
    if report.get("flags") != _FLAGS or report.get("operational_effects") != _EFFECTS:
        raise PatternClaimGraphError("Graph claims effects outside the offline boundary")
    expected = _derive(
        model, source_contexts=source_contexts, catalog=catalog,
        repository_root=repository_root,
    )
    if core.canonical(report) != core.canonical(expected):
        raise PatternClaimGraphError("Exported graph differs from original replay")
    return PatternClaimGraph._owned(expected)

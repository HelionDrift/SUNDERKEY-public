"""Unsigned cross-task claims over current offline specialist relation reports."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from . import offline_specialist_task_relations as relations

DOMAIN = "sunderkey.offline-collaboration-claim-graph.v1"
MAX_SOURCES = 4
MAX_CLAIMS = 32
MAX_HYPOTHESES = 16
MAX_REFERENCES = 64
MAX_BYTES = 262_144
MAX_NODES = 16_384
MAX_DEPTH = 16
MAX_TEXT = 512
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_STATUSES = {
    "matches_declared_expectation",
    "contradicts_declared_expectation",
    "unassessed",
}
_MATCH = "matches_declared_expectation"
_CONTRARY = "contradicts_declared_expectation"
_UNKNOWN = "unassessed"
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
    ),
    "none",
)


class OfflineCollaborationClaimGraphError(ValueError):
    """A closed graph, separate original or current-source replay was rejected."""


def _capture(value: Any, label: str) -> tuple[Any, str]:
    """Bound exact native JSON before copying or serializing shared subtrees."""
    count = size = 0
    active: set[int] = set()

    def visit(item: Any, depth: int) -> None:
        nonlocal count, size
        count += 1
        if count > MAX_NODES or depth > MAX_DEPTH:
            raise OfflineCollaborationClaimGraphError(f"{label} node/depth limit exceeded")
        family = type(item)
        if family is dict or family is list:
            if id(item) in active:
                raise OfflineCollaborationClaimGraphError(f"{label} cyclic input refused")
            size += 2 + max(len(item) - 1, 0)
            active.add(id(item))
            try:
                if family is dict:
                    size += len(item)
                    for key, child in item.items():
                        if type(key) is not str:
                            raise OfflineCollaborationClaimGraphError(
                                f"{label} native text keys required"
                            )
                        visit(key, depth + 1)
                        visit(child, depth + 1)
                else:
                    for child in item:
                        visit(child, depth + 1)
            finally:
                active.remove(id(item))
        elif family is str:
            if len(item) > MAX_TEXT or any(0xD800 <= ord(char) <= 0xDFFF for char in item):
                raise OfflineCollaborationClaimGraphError(f"{label} string limit exceeded")
            size += 2 + 12 * len(item)
        elif family is bool:
            size += 5
        elif family is int:
            if not -(1 << 63) <= item < (1 << 63):
                raise OfflineCollaborationClaimGraphError(f"{label} signed integer limit exceeded")
            size += len(str(item))
        elif item is None:
            size += 4
        else:
            raise OfflineCollaborationClaimGraphError(f"{label} unsupported native value")
        if size > 12 * MAX_BYTES:
            raise OfflineCollaborationClaimGraphError(f"{label} byte limit exceeded")

    visit(value, 1)
    text = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    if len(text) > MAX_BYTES:
        raise OfflineCollaborationClaimGraphError(f"{label} byte limit exceeded")
    return json.loads(text), text


def _fields(value: Any, names: set[str], label: str) -> None:
    if type(value) is not dict or value.keys() != names:
        raise OfflineCollaborationClaimGraphError(f"{label} fields are invalid")


def _identifier(value: Any, label: str) -> None:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise OfflineCollaborationClaimGraphError(f"{label} identifier is invalid")


def _plan(model: Any) -> dict:
    plan, _ = _capture(model, "graph model")
    _fields(
        plan,
        {"schema_version", "graph_label", "sources", "scope_bindings", "claims", "hypotheses"},
        "graph model",
    )
    if type(plan["schema_version"]) is not int or plan["schema_version"] != 1:
        raise OfflineCollaborationClaimGraphError("Graph schema version is invalid")
    _identifier(plan["graph_label"], "graph")
    sources = plan["sources"]
    claims = plan["claims"]
    bindings = plan["scope_bindings"]
    hypotheses = plan["hypotheses"]
    if (
        type(sources) is not list
        or not 2 <= len(sources) <= MAX_SOURCES
        or type(claims) is not list
        or not 2 <= len(claims) <= MAX_CLAIMS
        or type(bindings) is not list
        or not 1 <= len(bindings) <= MAX_CLAIMS
        or type(hypotheses) is not list
        or len(hypotheses) > MAX_HYPOTHESES
    ):
        raise OfflineCollaborationClaimGraphError("Graph cardinality is invalid")
    source_ids: set[str] = set()
    for source in sources:
        _fields(source, {"source_id"}, "source")
        _identifier(source["source_id"], "source")
        if source["source_id"] in source_ids:
            raise OfflineCollaborationClaimGraphError("Duplicate source identifier")
        source_ids.add(source["source_id"])
    claim_ids: set[str] = set()
    claim_scopes: dict[str, str] = {}
    for claim in claims:
        _fields(
            claim,
            {"claim_id", "source_id", "observation_kind", "observation_id", "scope_id"},
            "claim",
        )
        for key in ("claim_id", "source_id", "observation_id", "scope_id"):
            _identifier(claim[key], key)
        if claim["source_id"] not in source_ids or claim["claim_id"] in claim_ids:
            raise OfflineCollaborationClaimGraphError("Unknown source or duplicate claim")
        if claim["observation_kind"] not in ("premise", "hypothesis"):
            raise OfflineCollaborationClaimGraphError("Unknown observation kind")
        claim_ids.add(claim["claim_id"])
        claim_scopes[claim["claim_id"]] = claim["scope_id"]
    scopes: dict[str, set[str]] = {}
    for binding in bindings:
        _fields(binding, {"scope_id", "source_ids", "basis"}, "scope binding")
        _identifier(binding["scope_id"], "scope")
        members = binding["source_ids"]
        if type(members) is list:
            for member in members:
                _identifier(member, "bound source")
        if (
            binding["scope_id"] in scopes
            or type(members) is not list
            or len(members) < 2
            or len(members) > MAX_SOURCES
            or any(member not in source_ids for member in members)
            or len(set(members)) != len(members)
            or binding["basis"] != "caller_declared_unverified"
        ):
            raise OfflineCollaborationClaimGraphError("Scope binding is not explicit and closed")
        scopes[binding["scope_id"]] = set(members)
    for claim in claims:
        if claim["scope_id"] not in scopes or claim["source_id"] not in scopes[claim["scope_id"]]:
            raise OfflineCollaborationClaimGraphError(
                "Claim lacks its declared source-scope binding"
            )
    if set(scopes) != set(claim_scopes.values()):
        raise OfflineCollaborationClaimGraphError("Unused scope binding is refused")
    for scope_id, members in scopes.items():
        used = {c["source_id"] for c in claims if c["scope_id"] == scope_id}
        if used != members:
            raise OfflineCollaborationClaimGraphError(
                "Scope binding must name exactly its claim sources"
            )
    hypothesis_ids: set[str] = set()
    for hypothesis in hypotheses:
        _fields(hypothesis, {"hypothesis_id", "scope_id", "dependencies"}, "hypothesis")
        _identifier(hypothesis["hypothesis_id"], "hypothesis")
        _identifier(hypothesis["scope_id"], "hypothesis scope")
        if hypothesis["hypothesis_id"] in hypothesis_ids or hypothesis["scope_id"] not in scopes:
            raise OfflineCollaborationClaimGraphError("Duplicate hypothesis or unknown scope")
        hypothesis_ids.add(hypothesis["hypothesis_id"])
    references = 0
    by_hypothesis = {row["hypothesis_id"]: row for row in hypotheses}
    for hypothesis in hypotheses:
        deps = hypothesis["dependencies"]
        if type(deps) is not list or not deps:
            raise OfflineCollaborationClaimGraphError("Empty or nonnative dependency set")
        seen: set[tuple[str, str]] = set()
        for ref in deps:
            _fields(ref, {"kind", "id"}, "dependency")
            if type(ref["kind"]) is not str:
                raise OfflineCollaborationClaimGraphError("Dependency kind must be native text")
            _identifier(ref["id"], "dependency")
            key = (ref["kind"], ref["id"])
            if key in seen or ref["kind"] not in ("claim", "hypothesis"):
                raise OfflineCollaborationClaimGraphError("Duplicate or unknown typed dependency")
            seen.add(key)
            target_scope = (
                claim_scopes.get(ref["id"])
                if ref["kind"] == "claim"
                else by_hypothesis.get(ref["id"], {}).get("scope_id")
            )
            if target_scope != hypothesis["scope_id"]:
                raise OfflineCollaborationClaimGraphError(
                    "Missing dependency or cross-scope conjunction"
                )
            references += 1
        if references > MAX_REFERENCES:
            raise OfflineCollaborationClaimGraphError("Dependency reference limit exceeded")
    visited: set[str] = set()
    active: set[str] = set()

    def walk(identifier: str) -> None:
        if identifier in active:
            raise OfflineCollaborationClaimGraphError("Hypothesis cycle refused")
        if identifier in visited:
            return
        active.add(identifier)
        for ref in by_hypothesis[identifier]["dependencies"]:
            if ref["kind"] == "hypothesis":
                walk(ref["id"])
        active.remove(identifier)
        visited.add(identifier)

    for identifier in sorted(by_hypothesis):
        walk(identifier)
    return plan


def _digest(value: dict) -> str:
    content = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256((DOMAIN + "\n" + content).encode("ascii")).hexdigest()


def analyze_offline_collaboration_claim_graph(
    model: Any, *, source_contexts: Any, catalog: Any, repository_root: str | Path
) -> dict:
    """Replay each separate original once, then combine only declared-scope statuses."""
    plan = _plan(model)
    expected = {row["source_id"] for row in plan["sources"]}
    if type(source_contexts) is not dict or source_contexts.keys() != expected:
        raise OfflineCollaborationClaimGraphError("Exact separate source contexts required")
    for source_id, context in source_contexts.items():
        _fields(
            context, {"relation_report", "relation_model", "task_report", "task_model"}, source_id
        )
        if type(context["relation_report"]) is not relations.OfflineSpecialistTaskRelations:
            raise OfflineCollaborationClaimGraphError("Exact relation report wrapper required")
    verified: dict[str, dict] = {}
    for source_id in sorted(expected):
        context = source_contexts[source_id]
        try:
            report = relations.verify_offline_specialist_task_relations(
                context["relation_report"],
                model=context["relation_model"],
                task_report=context["task_report"],
                task_model=context["task_model"],
                catalog=catalog,
                repository_root=repository_root,
            )
            verified[source_id] = report.to_dict()
        except relations.OfflineSpecialistTaskRelationsError as exc:
            raise OfflineCollaborationClaimGraphError(
                f"Source {source_id} original/current replay failed"
            ) from exc
    task_addresses = [source["task_binding"]["task_result_sha256"] for source in verified.values()]
    if len(set(task_addresses)) != len(task_addresses):
        raise OfflineCollaborationClaimGraphError(
            "Repeated task evidence cannot masquerade as distinct graph sources"
        )
    observations: list[dict] = []
    statuses: dict[tuple[str, str], str] = {}
    for claim in sorted(plan["claims"], key=lambda row: row["claim_id"]):
        source = verified[claim["source_id"]]
        field = (
            "premise_observations"
            if claim["observation_kind"] == "premise"
            else "hypothesis_observations"
        )
        key = "premise_id" if claim["observation_kind"] == "premise" else "hypothesis_id"
        selected = [row for row in source[field] if row[key] == claim["observation_id"]]
        if len(selected) != 1 or selected[0]["status"] not in _STATUSES:
            raise OfflineCollaborationClaimGraphError("Claim selector lacks one typed observation")
        row = selected[0]
        observed = {
            **claim,
            "status": row["status"],
            "relation_analysis_id": source["analysis_id"],
            "relation_analysis_sha256": source["analysis_sha256"],
            "task_binding": source["task_binding"],
            "component_id": row["component_id"] if key == "premise_id" else None,
            "component_result_sha256": row["component_result_sha256"]
            if key == "premise_id"
            else None,
            "leaf_analysis_sha256": row["leaf_analysis_sha256"] if key == "premise_id" else None,
        }
        observations.append(observed)
        statuses[("claim", claim["claim_id"])] = row["status"]
    by_hypothesis = {row["hypothesis_id"]: row for row in plan["hypotheses"]}
    derived: dict[str, dict] = {}

    def evaluate(identifier: str) -> None:
        if identifier in derived:
            return
        hypothesis = by_hypothesis[identifier]
        deps = []
        for reference in sorted(
            hypothesis["dependencies"], key=lambda row: (row["kind"], row["id"])
        ):
            if reference["kind"] == "hypothesis":
                evaluate(reference["id"])
            deps.append({**reference, "status": statuses[(reference["kind"], reference["id"])]})
        values = {row["status"] for row in deps}
        status = _CONTRARY if _CONTRARY in values else (_UNKNOWN if _UNKNOWN in values else _MATCH)
        derived[identifier] = {
            "hypothesis_id": identifier,
            "scope_id": hypothesis["scope_id"],
            "dependencies": deps,
            "status": status,
        }
        statuses[("hypothesis", identifier)] = status

    for identifier in sorted(by_hypothesis):
        evaluate(identifier)
    report = {
        "schema_version": 1,
        "graph_label": plan["graph_label"],
        "source_model": plan,
        "source_bindings": [
            {
                "source_id": source_id,
                "analysis_id": verified[source_id]["analysis_id"],
                "analysis_sha256": verified[source_id]["analysis_sha256"],
                "task_binding": verified[source_id]["task_binding"],
            }
            for source_id in sorted(expected)
        ],
        "claim_observations": observations,
        "hypothesis_observations": [derived[key] for key in sorted(derived)],
        "flags": {
            "offline_only": True,
            "scope_equivalence_proven": False,
            "source_authenticated": False,
            "full_candidate_assembled": False,
            "positive_use_approved": False,
            "qualification_claimed": False,
        },
        "operational_effects": dict(_EFFECTS),
        "limitations": [
            "Scope links are declarations, not proof of shared target, tenant or identity.",
            "Leaf statuses are partial supplied observations, not pathways or findings.",
            "Original task and relation inputs plus current catalog are required for use.",
            "No target action, assignment, publication, authorization or qualification follows.",
        ],
    }
    _capture(report, "graph report")
    digest = _digest(report)
    report["graph_id"] = "OCG-" + digest[7:39].upper()
    report["graph_sha256"] = digest
    return _capture(report, "graph report")[0]


def verify_offline_collaboration_claim_graph(
    report: Any,
    *,
    model: Any,
    source_contexts: Any,
    catalog: Any,
    repository_root: str | Path,
) -> dict:
    """Rebuild from separate originals; graph address alone never verifies use."""
    supplied, text = _capture(report, "supplied graph report")
    expected = analyze_offline_collaboration_claim_graph(
        model, source_contexts=source_contexts, catalog=catalog, repository_root=repository_root
    )
    if text != _capture(expected, "expected graph report")[1]:
        raise OfflineCollaborationClaimGraphError("Graph differs from original/current derivation")
    return supplied

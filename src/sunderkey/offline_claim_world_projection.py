"""Project replayed claim matches into expiring hypothetical world facts only."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from . import attack_world_model as world
from . import offline_collaboration_claim_graph as graph

DOMAIN = "sunderkey.offline-claim-world-projection.v1"
MAX_NODES = 16
MAX_LINKS = 16
MAX_TECHNIQUES = 8
_UTC = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
_NODE_KINDS = {"asset", "principal", "identity", "endpoint", "service", "data_store", "trust_zone"}
_MATCH = "matches_declared_expectation"
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
MAX_REPORT_BYTES = 262_144
MAX_REPORT_NODES = 16_384
MAX_REPORT_DEPTH = 16


class OfflineClaimWorldProjectionError(ValueError):
    """Closed projection, replay, time, or hypothesis-only boundary failed."""


def _fields(value: Any, expected: set[str], label: str) -> None:
    if type(value) is not dict or value.keys() != expected:
        raise OfflineClaimWorldProjectionError(f"{label} fields are invalid")


def _capture_report(value: Any) -> tuple[dict, str]:
    """Bound the world model's sole 0.0 confidence scalar before JSON copying."""
    nodes = 0
    active: set[int] = set()

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_REPORT_NODES or depth > MAX_REPORT_DEPTH:
            raise OfflineClaimWorldProjectionError("World report node/depth limit exceeded")
        kind = type(item)
        if kind is dict or kind is list:
            if id(item) in active:
                raise OfflineClaimWorldProjectionError("Cyclic world report refused")
            active.add(id(item))
            try:
                if kind is dict:
                    for key, child in item.items():
                        if type(key) is not str:
                            raise OfflineClaimWorldProjectionError(
                                "Native text report keys required"
                            )
                        visit(key, depth + 1)
                        visit(child, depth + 1)
                else:
                    for child in item:
                        visit(child, depth + 1)
            finally:
                active.remove(id(item))
        elif kind is str:
            if len(item) > 512 or any(0xD800 <= ord(c) <= 0xDFFF for c in item):
                raise OfflineClaimWorldProjectionError("World report string limit exceeded")
        elif kind is int:
            if not -(1 << 63) <= item < 1 << 63:
                raise OfflineClaimWorldProjectionError("World report integer limit exceeded")
        elif kind is float:
            if item != 0.0:
                raise OfflineClaimWorldProjectionError("Only zero confidence is permitted")
        elif kind is not bool and item is not None:
            raise OfflineClaimWorldProjectionError("Unsupported native world report value")

    visit(value, 1)
    text = json.dumps(
        value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
    )
    if len(text) > MAX_REPORT_BYTES:
        raise OfflineClaimWorldProjectionError("World report byte limit exceeded")
    return json.loads(text), text


def _time(value: Any, label: str) -> datetime:
    if type(value) is not str or _UTC.fullmatch(value) is None:
        raise OfflineClaimWorldProjectionError(f"{label} must be second-precision UTC")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise OfflineClaimWorldProjectionError(f"{label} is invalid") from exc


def _plan(model: Any) -> dict:
    plan = graph._capture(model, "world projection model")[0]
    _fields(
        plan,
        {
            "schema_version",
            "projection_label",
            "scope_id",
            "projected_at",
            "expires_at",
            "nodes",
            "links",
        },
        "world projection model",
    )
    if type(plan["schema_version"]) is not int or plan["schema_version"] != 1:
        raise OfflineClaimWorldProjectionError("Projection schema version is invalid")
    graph._identifier(plan["projection_label"], "projection")
    graph._identifier(plan["scope_id"], "projection scope")
    projected = _time(plan["projected_at"], "projected_at")
    expires = _time(plan["expires_at"], "expires_at")
    lifetime = expires - projected
    if not timedelta(0) < lifetime <= timedelta(hours=24):
        raise OfflineClaimWorldProjectionError("Projection lifetime must be at most 24 hours")
    nodes = plan["nodes"]
    links = plan["links"]
    if (
        type(nodes) is not list
        or not 2 <= len(nodes) <= MAX_NODES
        or type(links) is not list
        or not 1 <= len(links) <= MAX_LINKS
    ):
        raise OfflineClaimWorldProjectionError("Projection cardinality is invalid")
    node_ids: set[str] = set()
    for node in nodes:
        _fields(node, {"node_id", "node_kind", "label"}, "projection node")
        graph._identifier(node["node_id"], "node")
        if type(node["node_kind"]) is not str or node["node_kind"] not in _NODE_KINDS:
            raise OfflineClaimWorldProjectionError("Projection node kind is not permitted")
        if (
            type(node["label"]) is not str
            or not node["label"]
            or len(node["label"]) > 256
            or any(not 32 <= ord(c) <= 126 for c in node["label"])
        ):
            raise OfflineClaimWorldProjectionError("Projection node label is invalid")
        if node["node_id"] in node_ids:
            raise OfflineClaimWorldProjectionError("Duplicate projection node")
        node_ids.add(node["node_id"])
    hypothesis_ids: set[str] = set()
    used_nodes: set[str] = set()
    for link in links:
        _fields(
            link,
            {"hypothesis_id", "source_node_id", "target_node_id", "technique_refs"},
            "projection link",
        )
        for field in ("hypothesis_id", "source_node_id", "target_node_id"):
            graph._identifier(link[field], field)
        if (
            link["hypothesis_id"] in hypothesis_ids
            or link["source_node_id"] not in node_ids
            or link["target_node_id"] not in node_ids
            or link["source_node_id"] == link["target_node_id"]
        ):
            raise OfflineClaimWorldProjectionError("Duplicate, dangling or self projection link")
        refs = link["technique_refs"]
        if type(refs) is not list or len(refs) > MAX_TECHNIQUES:
            raise OfflineClaimWorldProjectionError("Technique reference limit exceeded")
        for ref in refs:
            graph._identifier(ref, "technique")
        if len(set(refs)) != len(refs):
            raise OfflineClaimWorldProjectionError("Duplicate technique reference")
        hypothesis_ids.add(link["hypothesis_id"])
        used_nodes.update((link["source_node_id"], link["target_node_id"]))
    if used_nodes != node_ids:
        raise OfflineClaimWorldProjectionError("Every node must belong to a declared link")
    return plan


def _digest(body: dict) -> str:
    encoded = json.dumps(body, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256((DOMAIN + "\n" + encoded).encode("ascii")).hexdigest()


def project_offline_claims_to_world(
    model: Any,
    *,
    report: Any,
    graph_model: Any,
    source_contexts: Any,
    catalog: Any,
    repository_root: str | Path,
) -> dict:
    """Never produce verified, negative, reachable, or credential world facts."""
    plan = _plan(model)
    try:
        checked = graph.verify_offline_collaboration_claim_graph(
            report,
            model=graph_model,
            source_contexts=source_contexts,
            catalog=catalog,
            repository_root=repository_root,
        )
    except graph.OfflineCollaborationClaimGraphError as exc:
        raise OfflineClaimWorldProjectionError(
            "Original/current claim graph replay failed"
        ) from exc
    scopes = {row["scope_id"] for row in checked["source_model"]["scope_bindings"]}
    if plan["scope_id"] not in scopes:
        raise OfflineClaimWorldProjectionError("Projection scope is absent from graph")
    hypotheses = {
        row["hypothesis_id"]: row
        for row in checked["hypothesis_observations"]
        if row["scope_id"] == plan["scope_id"]
    }
    selected = {row["hypothesis_id"] for row in plan["links"]}
    if not hypotheses or selected != set(hypotheses):
        raise OfflineClaimWorldProjectionError(
            "Every hypothesis in the declared scope needs one link disposition"
        )
    evidence = world.EvidenceBinding(
        provenance_artifact_digest=checked["graph_sha256"],
        observed_at=plan["projected_at"],
        expires_at=plan["expires_at"],
        confidence=0.0,
        verification_state="hypothesis",
        source_kind="caller_declared_claim_graph",
    )
    try:
        nodes = [
            world.AttackNode(
                node_id=row["node_id"],
                node_kind=row["node_kind"],
                label=row["label"],
                scope_refs=(plan["scope_id"],),
                technique_refs=(),
                evidence=evidence,
            )
            for row in plan["nodes"]
        ]
        edges = []
        withheld = []
        for link in sorted(plan["links"], key=lambda row: row["hypothesis_id"]):
            observed = hypotheses[link["hypothesis_id"]]
            if observed["status"] != _MATCH:
                withheld.append(
                    {
                        "hypothesis_id": link["hypothesis_id"],
                        "status": observed["status"],
                        "reason": "not_a_matching_declared_hypothesis",
                    }
                )
                continue
            edges.append(
                world.AttackEdge(
                    fact_id="declared:" + link["hypothesis_id"],
                    source_node_id=link["source_node_id"],
                    target_node_id=link["target_node_id"],
                    edge_kind="inferred",
                    scope_refs=(plan["scope_id"],),
                    technique_refs=tuple(link["technique_refs"]),
                    evidence=evidence,
                )
            )
        snapshot = world.build_attack_world_snapshot(nodes, edges)
    except world.AttackWorldModelError as exc:
        raise OfflineClaimWorldProjectionError("Hypothesis-only world construction failed") from exc
    if any(
        row.evidence.verification_state is not world.VerificationState.HYPOTHESIS
        for row in (*snapshot.nodes, *snapshot.edges)
    ):
        raise OfflineClaimWorldProjectionError("Nonhypothetical world fact refused")
    body = {
        "schema_version": 1,
        "source_model": plan,
        "graph_id": checked["graph_id"],
        "graph_sha256": checked["graph_sha256"],
        "snapshot": snapshot.to_dict(),
        "withheld_links": withheld,
        "flags": {
            "caller_time_trusted": False,
            "scope_equivalence_proven": False,
            "source_authenticated": False,
            "verified_path_created": False,
            "positive_use_approved": False,
            "qualification_claimed": False,
        },
        "operational_effects": dict(_EFFECTS),
        "limitations": [
            "All projected facts are zero-confidence expiring hypotheses.",
            "Projection time and scope are caller declarations, not trusted observations.",
            "Contrary and unknown hypotheses create no world edge or negative fact.",
            "World queries remain planning outputs, not findings or action authority.",
        ],
    }
    _capture_report(body)
    digest = _digest(body)
    return _capture_report(
        {
            **body,
            "projection_id": "OWP-" + digest[7:39].upper(),
            "projection_sha256": digest,
        }
    )[0]


def verify_offline_claim_world_projection(
    packet: Any,
    *,
    model: Any,
    report: Any,
    graph_model: Any,
    source_contexts: Any,
    catalog: Any,
    repository_root: str | Path,
) -> dict:
    """Rebuild every world fact from current separate original claim sources."""
    supplied, text = _capture_report(packet)
    expected = project_offline_claims_to_world(
        model,
        report=report,
        graph_model=graph_model,
        source_contexts=source_contexts,
        catalog=catalog,
        repository_root=repository_root,
    )
    if text != _capture_report(expected)[1]:
        raise OfflineClaimWorldProjectionError("World projection differs from original derivation")
    return supplied

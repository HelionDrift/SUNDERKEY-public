"""Project caller-supplied third-party authority paths without target interaction."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "supplied_third_party_trust_path_projection"
PROFILE_ID = "AOE-GA-D04-S17"
CAPABILITY_ID = "army.ga.d04.s17"
VECTOR_ID = "AV-GA-D04-S17-01"
WORK_PACKAGE_ID = "IWP2-AOE-GA-D04-S17"
WAVE_ID = "IW2-001"
COMMANDER_ID = "AOE-GA-D04-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:3e14f4bfab98a997fa26556587145abf64d3de3c324172bea9fac8a3b2770ed9"
DOMAIN = "sunderkey.offline-third-party-trust-paths.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
MAX_NODES = 64
MAX_EDGES = 128
MAX_PATHS = 64
MAX_PATH_EDGES = 16
PARTY_KINDS = {"first_party", "msp", "third_party"}
RELATIONS = {"delegated_administration", "support_session", "api_trust", "service_dependency"}
AUTHORITY_STATES = {"authorized", "denied", "unknown"}
EFFECTS = {
    key: "none"
    for key in (
        "authority", "credentials", "execution", "filesystem", "finding_publication",
        "network", "process", "provider", "qualification", "target_interaction",
    )
}


class ThirdPartyTrustPathsError(ValueError):
    """Invalid or over-budget supplied trust model or original-source replay."""


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "inventory_complete", "nodes", "edges", "paths"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise ThirdPartyTrustPathsError("Exact schema version 1 required")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["inventory_complete"], "inventory completeness")
    nodes = core.bounded_list(model["nodes"], MAX_NODES, "nodes")
    edges = core.bounded_list(model["edges"], MAX_EDGES, "edges")
    paths = core.bounded_list(model["paths"], MAX_PATHS, "paths")
    if not nodes or not edges or not paths:
        raise ThirdPartyTrustPathsError("Nonempty bounded nodes, edges and paths required")

    node_kinds: dict[str, str] = {}
    for item in nodes:
        node = core.exact(item, {"node_id", "party_kind"}, "node")
        node_id = core.identifier(node["node_id"], "node ID")
        if node_id in node_kinds:
            raise ThirdPartyTrustPathsError("Duplicate node ID")
        node_kinds[node_id] = core.choice(node["party_kind"], PARTY_KINDS, "party kind")

    edge_map: dict[str, dict] = {}
    for item in edges:
        edge = core.exact(
            item,
            {"edge_id", "from_id", "to_id", "relation", "enabled", "authority_state"},
            "edge",
        )
        edge_id = core.identifier(edge["edge_id"], "edge ID")
        start = core.identifier(edge["from_id"], "edge source ID")
        end = core.identifier(edge["to_id"], "edge destination ID")
        if edge_id in edge_map or start not in node_kinds or end not in node_kinds or start == end:
            raise ThirdPartyTrustPathsError("Duplicate or invalid directed trust edge")
        core.choice(edge["relation"], RELATIONS, "trust relation")
        core.boolean(edge["enabled"], "edge enabled")
        core.choice(edge["authority_state"], AUTHORITY_STATES, "authority state")
        edge_map[edge_id] = edge

    path_ids: set[str] = set()
    path_sequences: set[tuple[str, ...]] = set()
    for item in paths:
        path = core.exact(
            item,
            {
                "path_id", "entry_id", "destination_id", "edge_ids",
                "context_complete", "claimed_authorized",
            },
            "path",
        )
        path_id = core.identifier(path["path_id"], "path ID")
        entry = core.identifier(path["entry_id"], "entry ID")
        destination = core.identifier(path["destination_id"], "destination ID")
        sequence = core.bounded_list(path["edge_ids"], MAX_PATH_EDGES, "path edges")
        for edge_id in sequence:
            core.identifier(edge_id, "path edge ID")
        if (
            path_id in path_ids
            or not sequence
            or len(sequence) != len(set(sequence))
            or tuple(sequence) in path_sequences
        ):
            raise ThirdPartyTrustPathsError("Unique nonempty path declaration required")
        if (
            node_kinds.get(entry) not in {"msp", "third_party"}
            or node_kinds.get(destination) != "first_party"
        ):
            raise ThirdPartyTrustPathsError(
                "External-party entry and first-party destination required"
            )
        current = entry
        for edge_id in sequence:
            edge = edge_map.get(edge_id)
            if edge is None or edge["from_id"] != current:
                raise ThirdPartyTrustPathsError("Declared path must follow known directed edges")
            current = edge["to_id"]
        if current != destination:
            raise ThirdPartyTrustPathsError("Declared path does not reach destination")
        core.boolean(path["context_complete"], "path context completeness")
        core.boolean(path["claimed_authorized"], "claimed authorization")
        path_ids.add(path_id)
        path_sequences.add(tuple(sequence))
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, source_text = _model(value)
    edge_map = {edge["edge_id"]: edge for edge in model["edges"]}
    rows = []
    for path in model["paths"]:
        traversed = [edge_map[edge_id] for edge_id in path["edge_ids"]]
        disabled = sorted(edge["edge_id"] for edge in traversed if not edge["enabled"])
        denied = sorted(
            edge["edge_id"] for edge in traversed if edge["authority_state"] == "denied"
        )
        unresolved = sorted(
            edge["edge_id"] for edge in traversed if edge["authority_state"] == "unknown"
        )
        complete = model["inventory_complete"] and path["context_complete"] and not unresolved
        computed: bool | None = None
        if complete:
            computed = not disabled and not denied
        mismatch = computed is not None and computed != path["claimed_authorized"]
        rows.append(
            {
                "path_id": path["path_id"],
                "entry_id": path["entry_id"],
                "destination_id": path["destination_id"],
                "edge_ids": list(path["edge_ids"]),
                "disabled_edge_ids": disabled,
                "denied_edge_ids": denied,
                "unknown_authority_edge_ids": unresolved,
                "claimed_authorized": path["claimed_authorized"],
                "computed_authorized": computed,
                "disposition": (
                    "unknown"
                    if computed is None
                    else "candidate_supplied_authority_mismatch"
                    if mismatch
                    else "matches_supplied_authority"
                ),
            }
        )
    candidates = sum(row["disposition"] == "candidate_supplied_authority_mismatch" for row in rows)
    unknowns = sum(row["disposition"] == "unknown" for row in rows)
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "wave_id": WAVE_ID,
        "commander_id": COMMANDER_ID,
        "independent_validator_id": INDEPENDENT_VALIDATOR_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(source_text.encode("ascii")),
        "source_model": model,
        "path_count": len(rows),
        "candidate_count": candidates,
        "unknown_count": unknowns,
        "path_observations": rows,
        "source_authenticated": False,
        "trust_relationship_verified": False,
        "authority_enforcement_verified": False,
        "compromise_or_lateral_access_verified": False,
        "positive_use_approved": False,
        "finding_claimed": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "bounds": {
            "model_bytes": MAX_MODEL_BYTES,
            "report_bytes": MAX_REPORT_BYTES,
            "nodes": MAX_NODES,
            "edges": MAX_EDGES,
            "paths": MAX_PATHS,
            "path_edges": MAX_PATH_EDGES,
        },
        "limitations": [
            "Organizations, relationships, edge authority, path claims and completeness "
            "are caller declarations.",
            "A candidate is a disagreement within supplied declarations, not verified "
            "compromise or access.",
            "Unknown edge authority or incomplete inventory or path context yields "
            "an unknown path result.",
            "No credential, MSP system, provider, network, process or target is contacted.",
            "No action authority, live finding, positive use or qualification is established.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="TPT-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class ThirdPartyTrustPathsReport:
    """Unsigned detached projection requiring independent original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise ThirdPartyTrustPathsError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> ThirdPartyTrustPathsReport:
        report = object.__new__(cls)
        object.__setattr__(report, "_document_json", core.canonical(document))
        return report

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_third_party_trust_paths(model: Any) -> ThirdPartyTrustPathsReport:
    """Compare only declared paths and edge authority states."""
    return ThirdPartyTrustPathsReport._owned(_derive(model))


def analyze_supplied_third_party_trust_paths_bytes(
    *, model_bytes: bytes
) -> ThirdPartyTrustPathsReport:
    model = core.decode(model_bytes, maximum=MAX_MODEL_BYTES)
    return analyze_supplied_third_party_trust_paths(model)


def verify_supplied_third_party_trust_paths(
    report: Any, *, model: Any
) -> ThirdPartyTrustPathsReport:
    """Replay against separately supplied original premises, not report contents."""
    if type(report) is not ThirdPartyTrustPathsReport:
        raise ThirdPartyTrustPathsError("Exact trust-path report wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise ThirdPartyTrustPathsError("Report differs from separately supplied original")
    return ThirdPartyTrustPathsReport._owned(expected)


def verify_supplied_third_party_trust_paths_bytes(
    report_bytes: bytes, *, model: Any
) -> ThirdPartyTrustPathsReport:
    """Reject changed exported reports against separately supplied original premises."""
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise ThirdPartyTrustPathsError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise ThirdPartyTrustPathsError("Exported report differs from original replay")
    return ThirdPartyTrustPathsReport._owned(expected)


def component_fixture() -> dict:
    """Fresh fictitious MSP path with a supplied authority contradiction."""
    return {
        "schema_version": 1,
        "source_id": "synthetic-partner-trust",
        "inventory_complete": True,
        "nodes": [
            {"node_id": "msp-a", "party_kind": "msp"},
            {"node_id": "support-bridge", "party_kind": "third_party"},
            {"node_id": "first-party-service", "party_kind": "first_party"},
        ],
        "edges": [
            {
                "edge_id": "support-delegation", "from_id": "msp-a", "to_id": "support-bridge",
                "relation": "support_session", "enabled": True,
                "authority_state": "authorized",
            },
            {
                "edge_id": "service-delegation", "from_id": "support-bridge",
                "to_id": "first-party-service", "relation": "delegated_administration",
                "enabled": True, "authority_state": "denied",
            },
        ],
        "paths": [
            {
                "path_id": "declared-msp-authority", "entry_id": "msp-a",
                "destination_id": "first-party-service",
                "edge_ids": ["support-delegation", "service-delegation"],
                "context_complete": True, "claimed_authorized": True,
            }
        ],
    }


__all__ = [
    "ThirdPartyTrustPathsError",
    "ThirdPartyTrustPathsReport",
    "analyze_supplied_third_party_trust_paths",
    "analyze_supplied_third_party_trust_paths_bytes",
    "verify_supplied_third_party_trust_paths",
    "verify_supplied_third_party_trust_paths_bytes",
    "component_fixture",
]

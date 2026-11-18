"""Project supplied directed directory trust declarations without authentication."""

from __future__ import annotations

import hashlib
import json
import re
from collections import deque
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "supplied_directory_trust_paths"
PROFILE_ID = "AOE-GC-D11-S06"
CAPABILITY_ID = "army.gc.d11.s06"
VECTOR_ID = "AV-GC-D11-S06-01"
WORK_PACKAGE_ID = "IWP2-AOE-GC-D11-S06"
WAVE_ID = "IW2-006"
COMMANDER_ID = "AOE-GC-D11-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:cb41c8d41aaacd3c5c45a71f122712e1654afc535bd302c40d01d2e801c0840b"
SEMANTICS_PROFILE = "supplied-directory-trust-paths-v1"
DOMAIN = "sunderkey.offline-directory-trust-paths.v1"
MAX_DOMAINS = 64
MAX_EDGES = 256
MAX_QUERIES = 16
MAX_DOCUMENT_BYTES = 524_288
MAX_NATIVE_NODES = 16_384
MAX_NATIVE_DEPTH = 12
MAX_STRING_LENGTH = 256
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_DOMAIN = re.compile(r"domain:sha256:[0-9a-f]{64}\Z")
_EFFECTS = dict.fromkeys(
    (
        "authority",
        "credential",
        "execution",
        "filesystem",
        "network",
        "publication",
        "qualification",
        "target",
    ),
    "none",
)


class DirectoryTrustPathsError(ValueError):
    """The supplied trust declarations or report were refused."""


def _canonical(value: Any) -> str:
    nodes = 0
    active: set[int] = set()

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_NATIVE_NODES or depth > MAX_NATIVE_DEPTH:
            raise DirectoryTrustPathsError("Native document structure bound exceeded")
        family = type(item)
        if family is str:
            if len(item) > MAX_STRING_LENGTH:
                raise DirectoryTrustPathsError("Native document string bound exceeded")
            return
        if family is bool or item is None:
            return
        if family is int:
            if not -(1 << 63) <= item < (1 << 63):
                raise DirectoryTrustPathsError("Native document integer bound exceeded")
            return
        if family not in (dict, list):
            raise DirectoryTrustPathsError("Only exact native JSON values are accepted")
        if id(item) in active:
            raise DirectoryTrustPathsError("Cyclic native document refused")
        active.add(id(item))
        try:
            if family is dict:
                for key, child in item.items():
                    if type(key) is not str:
                        raise DirectoryTrustPathsError("Native JSON text keys are required")
                    visit(key, depth + 1)
                    visit(child, depth + 1)
            else:
                for child in item:
                    visit(child, depth + 1)
        finally:
            active.remove(id(item))

    visit(value, 1)
    encoded = json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False
    )
    if len(encoded) > MAX_DOCUMENT_BYTES:
        raise DirectoryTrustPathsError("Document byte bound exceeded")
    return encoded


def _fields(value: Any, names: set[str], label: str) -> None:
    if type(value) is not dict or value.keys() != names:
        raise DirectoryTrustPathsError(f"{label} fields are invalid")


def _domain(value: Any) -> str:
    if type(value) is not str or _DOMAIN.fullmatch(value) is None:
        raise DirectoryTrustPathsError("Opaque domain reference is required")
    return value


def _plan(model: Any) -> dict:
    model = json.loads(_canonical(model))
    _fields(
        model,
        {
            "schema_version",
            "semantics_profile",
            "inventory_complete",
            "domains",
            "trusts",
            "queries",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise DirectoryTrustPathsError("Schema version is invalid")
    if model["semantics_profile"] != SEMANTICS_PROFILE:
        raise DirectoryTrustPathsError("Semantics profile is invalid")
    if type(model["inventory_complete"]) is not bool:
        raise DirectoryTrustPathsError("Completeness must be an exact boolean")
    domains = model["domains"]
    if type(domains) is not list or not 2 <= len(domains) <= MAX_DOMAINS:
        raise DirectoryTrustPathsError("Domain count is invalid")
    known_domains: set[str] = set()
    for value in domains:
        value = _domain(value)
        if value in known_domains:
            raise DirectoryTrustPathsError("Duplicate domain reference")
        known_domains.add(value)
    trusts = model["trusts"]
    if type(trusts) is not list or len(trusts) > MAX_EDGES:
        raise DirectoryTrustPathsError("Trust count is invalid")
    edge_ids: set[str] = set()
    for trust in trusts:
        _fields(
            trust,
            {
                "edge_id",
                "from_domain_ref",
                "to_domain_ref",
                "enabled",
                "supplied_chainable",
                "selective_authentication",
                "sid_filtering",
            },
            "trust",
        )
        edge_id = trust["edge_id"]
        if type(edge_id) is not str or _ID.fullmatch(edge_id) is None or edge_id in edge_ids:
            raise DirectoryTrustPathsError("Trust edge identifier is invalid or duplicate")
        edge_ids.add(edge_id)
        source, target = _domain(trust["from_domain_ref"]), _domain(trust["to_domain_ref"])
        if source not in known_domains or target not in known_domains or source == target:
            raise DirectoryTrustPathsError("Trust endpoint is unknown or self-referential")
        for key in ("enabled", "supplied_chainable", "selective_authentication", "sid_filtering"):
            if type(trust[key]) is not bool:
                raise DirectoryTrustPathsError("Trust gate fields must be exact booleans")
    queries = model["queries"]
    if type(queries) is not list or not 1 <= len(queries) <= MAX_QUERIES:
        raise DirectoryTrustPathsError("Query count is invalid")
    seen_queries: set[tuple[str, str]] = set()
    for query in queries:
        _fields(query, {"from_domain_ref", "to_domain_ref"}, "query")
        source, target = _domain(query["from_domain_ref"]), _domain(query["to_domain_ref"])
        if source not in known_domains or target not in known_domains or source == target:
            raise DirectoryTrustPathsError("Query endpoint is unknown or self-referential")
        if (source, target) in seen_queries:
            raise DirectoryTrustPathsError("Duplicate query")
        seen_queries.add((source, target))
    return model


def _path(source: str, target: str, adjacency: dict[str, list[dict]]) -> list[dict] | None:
    queue = deque([(source, (), True)])
    seen = {(source, True)}
    while queue:
        current, path, can_expand = queue.popleft()
        if current == target and path:
            return list(path)
        if not can_expand:
            continue
        for edge in sorted(adjacency.get(current, []), key=lambda item: item["edge_id"]):
            next_state = (edge["to_domain_ref"], edge["supplied_chainable"])
            if next_state in seen:
                continue
            seen.add(next_state)
            queue.append((edge["to_domain_ref"], (*path, edge), edge["supplied_chainable"]))
    return None


def _derive(model: Any) -> dict:
    plan = _plan(model)
    adjacency: dict[str, list[dict]] = {}
    for edge in plan["trusts"]:
        if edge["enabled"]:
            adjacency.setdefault(edge["from_domain_ref"], []).append(edge)
    rows = []
    for query in plan["queries"]:
        found = _path(query["from_domain_ref"], query["to_domain_ref"], adjacency)
        if found is None:
            disposition = (
                "no_supplied_enabled_path"
                if plan["inventory_complete"]
                else "unknown_incomplete_inventory"
            )
            edge_ids: list[str] = []
            selective = filtering = False
        else:
            disposition = (
                "supplied_enabled_path_with_gates"
                if any(edge["selective_authentication"] or edge["sid_filtering"] for edge in found)
                else "supplied_enabled_path"
            )
            edge_ids = [edge["edge_id"] for edge in found]
            selective = any(edge["selective_authentication"] for edge in found)
            filtering = any(edge["sid_filtering"] for edge in found)
        rows.append(
            {
                "from_domain_ref": query["from_domain_ref"],
                "to_domain_ref": query["to_domain_ref"],
                "disposition": disposition,
                "trust_edge_ids": edge_ids,
                "selective_authentication_declared": selective,
                "sid_filtering_declared": filtering,
            }
        )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "source_model": plan,
        "queries": rows,
        "flags": {
            "directory_source_authenticated": False,
            "domain_identity_proven": False,
            "trust_configuration_proven": False,
            "authentication_or_authorization_proven": False,
            "real_path_absence_proven": False,
            "positive_use_approved": False,
            "qualification_claimed": False,
        },
        "operational_effects": dict(_EFFECTS),
        "limitations": [
            "Domain, direction, enabled state, chainability, gates, and completeness are supplied.",
            "Selective authentication and SID filtering are labels, not evaluated controls.",
            "A directed path does not prove authentication, authorization, or lateral access.",
            "No directory, credential, network, service, or target is contacted.",
        ],
    }
    digest = (
        "sha256:" + hashlib.sha256((DOMAIN + "\n" + _canonical(body)).encode("ascii")).hexdigest()
    )
    return json.loads(
        _canonical(
            {**body, "analysis_id": "DTP-" + digest[7:39].upper(), "analysis_sha256": digest}
        )
    )


@dataclass(frozen=True, slots=True, init=False)
class DirectoryTrustPaths:
    """Replay-checked projection of caller-supplied trust declarations."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        if type(document) is not dict or type(document.get("source_model")) is not dict:
            raise DirectoryTrustPathsError("Exact native report with source model required")
        expected = _derive(document["source_model"])
        if _canonical(document) != _canonical(expected):
            raise DirectoryTrustPathsError("Report differs from embedded model replay")
        object.__setattr__(self, "_document_json", _canonical(expected))

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_directory_trusts(model: Any) -> DirectoryTrustPaths:
    """Project only directed supplied trust declarations."""
    return DirectoryTrustPaths(_derive(model))


def verify_supplied_directory_trusts(report: Any, *, model: Any) -> DirectoryTrustPaths:
    """Recompute a report from current supplied model bytes."""
    if type(report) is not DirectoryTrustPaths:
        raise DirectoryTrustPathsError("Exact native analysis wrapper required")
    expected = _derive(model)
    if report.to_json() != _canonical(expected):
        raise DirectoryTrustPathsError("Report differs from supplied model replay")
    return DirectoryTrustPaths(expected)

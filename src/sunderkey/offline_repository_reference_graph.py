"""Project declared repository references without cloning or resolving refs."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

COMPONENT_ID = "supplied_repository_reference_graph"
PROFILE_ID = "AOE-GA-D01-S07"
CAPABILITY_ID = "army.ga.d01.s07"
VECTOR_ID = "AV-GA-D01-S07-01"
WORK_PACKAGE_ID = "IWP2-AOE-GA-D01-S07"
WAVE_ID = "IW2-007"
COMMANDER_ID = "AOE-GA-D01-CMD"
GROUP_OWNER_ID = "AOE-HQ-03"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:c1bc7c5f76e7866356e13d836ef9226703f466b9006d1abf1c8925dd98ff6660"
SEMANTICS_PROFILE = "supplied-repository-reference-graph-v1"
DOMAIN = "sunderkey.offline-repository-reference-graph.v1"
MAX_REPOSITORIES = 256
MAX_REFERENCES = 512
MAX_DOCUMENT_BYTES = 262_144
MAX_NATIVE_NODES = 16_384
MAX_NATIVE_DEPTH = 12
MAX_STRING_LENGTH = 256
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z")
_COMMIT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_VISIBILITY = frozenset({"public", "private", "internal", "unknown"})
_SELECTOR_KINDS = frozenset({"commit", "branch", "tag"})
_EFFECTS = dict.fromkeys(
    (
        "authority",
        "credential",
        "execution",
        "filesystem",
        "git_clone",
        "network",
        "provider",
        "publication",
        "qualification",
        "repository_write",
        "target",
    ),
    "none",
)


class RepositoryReferenceGraphError(ValueError):
    """The bounded metadata model or replay report was refused."""


def _fields(value: Any, names: set[str], label: str) -> None:
    if type(value) is not dict or value.keys() != names:
        raise RepositoryReferenceGraphError(f"{label} fields are invalid")


def _identifier(value: Any, label: str) -> None:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise RepositoryReferenceGraphError(f"{label} identifier is invalid")


def _canonical(value: Any) -> str:
    nodes = 0
    active: set[int] = set()

    def visit(item: Any, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_NATIVE_NODES or depth > MAX_NATIVE_DEPTH:
            raise RepositoryReferenceGraphError("Native document structure bound exceeded")
        family = type(item)
        if family is str:
            if len(item) > MAX_STRING_LENGTH:
                raise RepositoryReferenceGraphError("Native document string bound exceeded")
            return
        if family is bool or item is None:
            return
        if family is int:
            if not -(1 << 63) <= item < (1 << 63):
                raise RepositoryReferenceGraphError("Native document integer bound exceeded")
            return
        if family not in (dict, list):
            raise RepositoryReferenceGraphError("Only exact native JSON values are accepted")
        if id(item) in active:
            raise RepositoryReferenceGraphError("Cyclic native document refused")
        active.add(id(item))
        try:
            if family is dict:
                for key, child in item.items():
                    if type(key) is not str:
                        raise RepositoryReferenceGraphError("Native JSON text keys are required")
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
        raise RepositoryReferenceGraphError("Document byte bound exceeded")
    return encoded


def _plan(model: Any) -> tuple[dict, dict[str, dict], list[dict]]:
    _fields(model, {"schema_version", "semantics_profile", "repositories", "references"}, "model")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise RepositoryReferenceGraphError("Schema version is invalid")
    if model["semantics_profile"] != SEMANTICS_PROFILE:
        raise RepositoryReferenceGraphError("Semantics profile is invalid")
    repositories = model["repositories"]
    references = model["references"]
    if type(repositories) is not list or not 1 <= len(repositories) <= MAX_REPOSITORIES:
        raise RepositoryReferenceGraphError("Repository count is invalid")
    if type(references) is not list or not 1 <= len(references) <= MAX_REFERENCES:
        raise RepositoryReferenceGraphError("Reference count is invalid")
    by_id: dict[str, dict] = {}
    for repository in repositories:
        _fields(repository, {"repo_id", "owner_id", "visibility", "source_id"}, "repository")
        for field in ("repo_id", "owner_id", "source_id"):
            _identifier(repository[field], field)
        if type(repository["visibility"]) is not str or repository["visibility"] not in _VISIBILITY:
            raise RepositoryReferenceGraphError("Repository visibility is invalid")
        if repository["repo_id"] in by_id:
            raise RepositoryReferenceGraphError("Duplicate repository identifier")
        by_id[repository["repo_id"]] = repository
    reference_ids: set[str] = set()
    signatures: set[tuple[str, str, str, str, str]] = set()
    for reference in references:
        _fields(
            reference,
            {
                "reference_id",
                "from_repo_id",
                "to_repo_id",
                "selector_kind",
                "selector",
                "source_id",
            },
            "reference",
        )
        for field in ("reference_id", "from_repo_id", "to_repo_id", "source_id"):
            _identifier(reference[field], field)
        if reference["from_repo_id"] not in by_id:
            raise RepositoryReferenceGraphError("Reference source repository is not supplied")
        kind = reference["selector_kind"]
        if type(kind) is not str or kind not in _SELECTOR_KINDS:
            raise RepositoryReferenceGraphError("Selector kind is invalid")
        if kind == "commit":
            if (
                type(reference["selector"]) is not str
                or _COMMIT.fullmatch(reference["selector"]) is None
            ):
                raise RepositoryReferenceGraphError("Commit selector syntax is invalid")
        else:
            _identifier(reference["selector"], "selector")
        signature = (
            reference["from_repo_id"],
            reference["to_repo_id"],
            kind,
            reference["selector"],
            reference["source_id"],
        )
        if reference["reference_id"] in reference_ids or signature in signatures:
            raise RepositoryReferenceGraphError("Duplicate supplied reference")
        reference_ids.add(reference["reference_id"])
        signatures.add(signature)
    return json.loads(_canonical(model)), by_id, references


def _derive(model: Any) -> dict:
    plan, by_id, references = _plan(model)
    observations = []
    for reference in sorted(references, key=lambda row: row["reference_id"]):
        source = by_id[reference["from_repo_id"]]
        target = by_id.get(reference["to_repo_id"])
        observations.append(
            {
                "reference_id": reference["reference_id"],
                "from_repo_id": reference["from_repo_id"],
                "to_repo_id": reference["to_repo_id"],
                "source_id": reference["source_id"],
                "selector_class": (
                    "syntactic_commit_digest"
                    if reference["selector_kind"] == "commit"
                    else "named_ref"
                ),
                "owner_relation": (
                    "unresolved_supplied_target"
                    if target is None
                    else "same_declared_owner"
                    if source["owner_id"] == target["owner_id"]
                    else "different_declared_owner"
                ),
                "target_visibility": target["visibility"] if target else "not_supplied",
                "source_repository_label": source["source_id"],
                "target_repository_label": target["source_id"] if target else None,
            }
        )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "source_model": plan,
        "observations": observations,
        "flags": {
            "repository_metadata_authenticated": False,
            "repository_visibility_proven": False,
            "ownership_proven": False,
            "commit_existence_proven": False,
            "ref_immutability_proven": False,
            "target_existence_proven": False,
            "positive_use_approved": False,
            "qualification_claimed": False,
        },
        "operational_effects": dict(_EFFECTS),
        "limitations": [
            "Repository, owner, visibility and reference labels are caller-supplied.",
            "A syntactic commit digest is not proof that an object exists or is pinned in use.",
            "Named refs may change, but this comparison does not resolve or fetch them.",
            "No repository clone, provider API, credential or target is contacted.",
        ],
    }
    digest = (
        "sha256:" + hashlib.sha256((DOMAIN + "\n" + _canonical(body)).encode("ascii")).hexdigest()
    )
    return json.loads(
        _canonical(
            {**body, "analysis_id": "RRG-" + digest[7:39].upper(), "analysis_sha256": digest}
        )
    )


@dataclass(frozen=True, slots=True, init=False)
class RepositoryReferenceGraph:
    """Replay-checked supplied reference projection with no Git or provider I/O."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        if type(document) is not dict or type(document.get("source_model")) is not dict:
            raise RepositoryReferenceGraphError("Exact native report with source model required")
        expected = _derive(document["source_model"])
        if _canonical(document) != _canonical(expected):
            raise RepositoryReferenceGraphError("Report differs from embedded model replay")
        object.__setattr__(self, "_document_json", _canonical(expected))

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_repository_references(model: Any) -> RepositoryReferenceGraph:
    """Project supplied references without asserting repo or commit existence."""
    return RepositoryReferenceGraph(_derive(model))


def verify_supplied_repository_references(report: Any, *, model: Any) -> RepositoryReferenceGraph:
    """Independently rederive the supplied reference model."""
    if type(report) is not RepositoryReferenceGraph:
        raise RepositoryReferenceGraphError("Exact native analysis wrapper required")
    expected = _derive(model)
    if report.to_json() != _canonical(expected):
        raise RepositoryReferenceGraphError("Report differs from supplied model replay")
    return RepositoryReferenceGraph(expected)


__all__ = [
    "COMPONENT_ID",
    "PROFILE_ID",
    "RepositoryReferenceGraph",
    "RepositoryReferenceGraphError",
    "analyze_supplied_repository_references",
    "verify_supplied_repository_references",
]

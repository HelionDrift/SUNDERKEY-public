"""Project declared query construction without generating query text."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "supplied_query_input_boundary"
PROFILE_ID = "AOE-GE-D23-S01"
CAPABILITY_ID = "army.ge.d23.s01"
VECTOR_ID = "AV-GE-D23-S01-01"
WORK_PACKAGE_ID = "IWP2-AOE-GE-D23-S01"
WAVE_ID = "IW2-015"
COMMANDER_ID = "AOE-GE-D23-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:cb93e5262dc418184ef9911d68e00a8feed5f2d184bc545cf0fb3cf9ebb95582"
SEMANTICS_PROFILE = "supplied-query-input-boundary-v1"
DOMAIN = "sunderkey.offline-query-input-boundary.v1"
MAX_SOURCE_BYTES = 32_768
MAX_REPORT_BYTES = 65_536
MAX_QUERIES = 64
MAX_INPUTS = 16
_REF = re.compile(r"ref:[A-Za-z0-9][A-Za-z0-9._:-]{0,63}\Z")
_FAMILIES = {"relational", "document", "graph", "search"}
_TRUST = {"trusted", "untrusted", "unknown"}
_INCORPORATION = {"parameter_bind", "trusted_literal", "interpolation", "unknown"}
_EFFECTS = dict.fromkeys(
    ("authority", "credential", "execution", "filesystem", "network",
     "publication", "qualification", "target"),
    "none",
)

QueryInputBoundaryError = core.FrameworkDeclarationError


def _reference(value: Any) -> str:
    if type(value) is not str or _REF.fullmatch(value) is None:
        raise QueryInputBoundaryError("Input label must be an opaque reference")
    return value


def _model(value: Any) -> dict:
    core.validate_tree(value, maximum=MAX_SOURCE_BYTES)
    model = json.loads(core.canonical(value))
    item = core.exact(
        model,
        {"schema_version", "semantics_profile", "source_id", "policy", "queries"},
        "model",
    )
    if type(item["schema_version"]) is not int or item["schema_version"] != 1:
        raise QueryInputBoundaryError("Schema version is invalid")
    if item["semantics_profile"] != SEMANTICS_PROFILE:
        raise QueryInputBoundaryError("Semantics profile is invalid")
    core.identifier(item["source_id"], "source ID")
    policy = core.exact(
        item["policy"], {"declaration_complete", "parameter_binding_required"}, "policy"
    )
    core.boolean(policy["declaration_complete"], "policy completeness")
    core.boolean(policy["parameter_binding_required"], "parameter binding requirement")
    queries = core.bounded_list(item["queries"], MAX_QUERIES, "queries")
    if not queries:
        raise QueryInputBoundaryError("At least one query is required")
    query_ids: set[str] = set()
    for raw in queries:
        query = core.exact(
            raw,
            {"query_id", "query_family", "inputs", "execution_declared", "capture_complete"},
            "query",
        )
        identity = core.identifier(query["query_id"], "query ID")
        if identity in query_ids:
            raise QueryInputBoundaryError("Query identifier is repeated")
        query_ids.add(identity)
        core.choice(query["query_family"], _FAMILIES, "query family")
        core.boolean(query["execution_declared"], "execution declaration")
        core.boolean(query["capture_complete"], "capture completeness")
        inputs = core.bounded_list(query["inputs"], MAX_INPUTS, "inputs")
        if not inputs:
            raise QueryInputBoundaryError("At least one input is required")
        input_ids: set[str] = set()
        for raw_input in inputs:
            entry = core.exact(
                raw_input, {"input_ref", "source_trust", "incorporation"}, "input"
            )
            source_ref = _reference(entry["input_ref"])
            if source_ref in input_ids:
                raise QueryInputBoundaryError("Input reference is repeated")
            input_ids.add(source_ref)
            core.choice(entry["source_trust"], _TRUST, "source trust")
            core.choice(entry["incorporation"], _INCORPORATION, "incorporation")
            if (
                entry["incorporation"] == "trusted_literal"
                and entry["source_trust"] != "trusted"
            ):
                raise QueryInputBoundaryError("Trusted literal requires a trusted source")
    return model


def _derive(value: Any) -> dict:
    model = _model(value)
    projections = []
    for item in sorted(model["queries"], key=lambda row: row["query_id"]):
        unresolved = any(
            entry["source_trust"] == "unknown" or entry["incorporation"] == "unknown"
            for entry in item["inputs"]
        )
        unbound = sorted(
            entry["input_ref"] for entry in item["inputs"]
            if entry["source_trust"] == "untrusted"
            and entry["incorporation"] == "interpolation"
        )
        negative = model["policy"]["parameter_binding_required"] and bool(unbound)
        if not model["policy"]["declaration_complete"] or not item["capture_complete"]:
            disposition = "unresolved_declaration_or_capture"
        elif unresolved:
            disposition = "unresolved_input_trust_or_incorporation"
        elif not negative:
            disposition = "no_declared_unbound_query_input"
        elif not item["execution_declared"]:
            disposition = "declared_unexecuted_query_construction_conflict"
        else:
            disposition = "candidate_declared_query_input_boundary_conflict"
        projections.append(
            {"query_id": item["query_id"], "unbound_input_refs": unbound,
             "negative_predicate": "untrusted_query_input_requires_binding" if negative else None,
             "disposition": disposition}
        )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "source_model": model,
        "query_count": len(projections),
        "projections": projections,
        "flags": {
            "query_text_parsed": False,
            "query_execution_verified": False,
            "injection_verified": False,
            "positive_use_approved": False,
            "qualification_claimed": False,
        },
        "operational_effects": dict(_EFFECTS),
        "limitations": [
            "Query family, input trust, incorporation and execution are caller assertions.",
            "No query text or injection payload is accepted or generated.",
            "A declared construction conflict does not verify query injection.",
            "No file, credential, network, process or target is accessed.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="QIB-")
    report = {**body, "analysis_id": report_id, "analysis_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return json.loads(core.canonical(report))


@dataclass(frozen=True, slots=True, init=False)
class QueryInputBoundary:
    """Immutable replay of one supplied query-construction model."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        if type(document) is not dict or type(document.get("source_model")) is not dict:
            raise QueryInputBoundaryError("Exact native report with source model required")
        expected = _derive(document["source_model"])
        core.validate_tree(document, maximum=MAX_REPORT_BYTES)
        if core.canonical(document) != core.canonical(expected):
            raise QueryInputBoundaryError("Report differs from embedded source replay")
        object.__setattr__(self, "_document_json", core.canonical(expected))

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_query_input_boundary(model: Any) -> QueryInputBoundary:
    """Project supplied input incorporation without constructing a query."""
    return QueryInputBoundary(_derive(model))


def verify_supplied_query_input_boundary(
    report: Any, *, model: Any
) -> QueryInputBoundary:
    if type(report) is not QueryInputBoundary:
        raise QueryInputBoundaryError("Exact native analysis wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise QueryInputBoundaryError("Report differs from supplied source replay")
    return QueryInputBoundary(expected)

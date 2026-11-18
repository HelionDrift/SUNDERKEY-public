"""Project supplied requester and deputy authority across one operation."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "supplied_confused_deputy_boundary"
PROFILE_ID = "AOE-GE-D23-S14"
CAPABILITY_ID = "pattern.confused-deputy-trust-boundary"
VECTOR_ID = "AV-GE-D23-S14-01"
WORK_PACKAGE_ID = "IWP2-AOE-GE-D23-S14"
WAVE_ID = "IW2-028"
COMMANDER_ID = "AOE-GE-D23-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:9971c2d6177581e9c097812df243b54b6cb7015e566777668603213fa0bb330d"
SEMANTICS_PROFILE = "supplied-requester-deputy-boundary-v1"
DOMAIN = "sunderkey.offline-confused-deputy-boundary.v1"
MAX_SOURCE_BYTES = 32_768
MAX_REPORT_BYTES = 65_536
MAX_OPERATIONS = 128
_REF = re.compile(r"ref:[A-Za-z0-9][A-Za-z0-9._:-]{0,63}\Z")
_AUTHORITY = {"allow", "deny", "unknown"}
_EFFECTS = dict.fromkeys(
    ("authority", "credential", "execution", "filesystem", "network",
     "publication", "qualification", "target"),
    "none",
)

ConfusedDeputyBoundaryError = core.FrameworkDeclarationError


def _reference(value: Any) -> str:
    if type(value) is not str or _REF.fullmatch(value) is None:
        raise ConfusedDeputyBoundaryError("Actor and resource labels must be opaque references")
    return value


def _model(value: Any) -> dict:
    core.validate_tree(value, maximum=MAX_SOURCE_BYTES)
    model = json.loads(core.canonical(value))
    item = core.exact(
        model,
        {"schema_version", "semantics_profile", "source_id", "policy", "operations"},
        "model",
    )
    if type(item["schema_version"]) is not int or item["schema_version"] != 1:
        raise ConfusedDeputyBoundaryError("Schema version is invalid")
    if item["semantics_profile"] != SEMANTICS_PROFILE:
        raise ConfusedDeputyBoundaryError("Semantics profile is invalid")
    core.identifier(item["source_id"], "source ID")
    policy = core.exact(
        item["policy"], {"declaration_complete", "requester_authority_required"}, "policy"
    )
    core.boolean(policy["declaration_complete"], "policy completeness")
    core.boolean(policy["requester_authority_required"], "requester authority requirement")
    operations = core.bounded_list(item["operations"], MAX_OPERATIONS, "operations")
    if not operations:
        raise ConfusedDeputyBoundaryError("At least one operation is required")
    identifiers: set[str] = set()
    for raw in operations:
        operation = core.exact(
            raw,
            {"operation_id", "requester_ref", "deputy_ref", "resource_ref",
             "requester_authority", "deputy_authority", "delegation_declared",
             "declared_result", "capture_complete"},
            "operation",
        )
        identity = core.identifier(operation["operation_id"], "operation ID")
        if identity in identifiers:
            raise ConfusedDeputyBoundaryError("Operation identifier is repeated")
        identifiers.add(identity)
        for field in ("requester_ref", "deputy_ref", "resource_ref"):
            _reference(operation[field])
        if operation["requester_ref"] == operation["deputy_ref"]:
            raise ConfusedDeputyBoundaryError("Requester and deputy must differ")
        for field in ("requester_authority", "deputy_authority", "declared_result"):
            core.choice(operation[field], _AUTHORITY, field)
        core.boolean(operation["delegation_declared"], "delegation declaration")
        core.boolean(operation["capture_complete"], "capture completeness")
    return model


def _derive(value: Any) -> dict:
    model = _model(value)
    projections = []
    for item in sorted(model["operations"], key=lambda row: row["operation_id"]):
        negative = (
            model["policy"]["requester_authority_required"]
            and item["delegation_declared"]
            and item["requester_authority"] == "deny"
            and item["deputy_authority"] == "allow"
        )
        if not model["policy"]["declaration_complete"] or not item["capture_complete"]:
            disposition = "unresolved_declaration_or_capture"
        elif "unknown" in (
            item["requester_authority"], item["deputy_authority"], item["declared_result"]
        ):
            disposition = "unresolved_authority_or_result"
        elif not negative:
            disposition = "no_declared_deputy_boundary_conflict"
        elif item["declared_result"] == "allow":
            disposition = "candidate_declared_deputy_boundary_conflict"
        else:
            disposition = "declared_requester_boundary_consistent"
        projections.append(
            {"operation_id": item["operation_id"],
             "negative_predicate": "requester_deny_requires_deny" if negative else None,
             "disposition": disposition}
        )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "source_model": model,
        "operation_count": len(projections),
        "projections": projections,
        "flags": {
            "requester_authority_verified": False,
            "deputy_authority_verified": False,
            "delegated_operation_verified": False,
            "boundary_crossing_verified": False,
            "positive_use_approved": False,
            "qualification_claimed": False,
        },
        "operational_effects": dict(_EFFECTS),
        "limitations": [
            "Actors, resource, authority, delegation and result are caller assertions.",
            "A declared conflict does not verify a confused-deputy path.",
            "The model does not infer actual delegation or platform authority semantics.",
            "No file, credential, network, process or target is accessed.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="CDB-")
    report = {**body, "analysis_id": report_id, "analysis_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return json.loads(core.canonical(report))


@dataclass(frozen=True, slots=True, init=False)
class ConfusedDeputyBoundary:
    """Immutable replay of one supplied deputy-boundary model."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        if type(document) is not dict or type(document.get("source_model")) is not dict:
            raise ConfusedDeputyBoundaryError("Exact native report with source model required")
        expected = _derive(document["source_model"])
        core.validate_tree(document, maximum=MAX_REPORT_BYTES)
        if core.canonical(document) != core.canonical(expected):
            raise ConfusedDeputyBoundaryError("Report differs from embedded source replay")
        object.__setattr__(self, "_document_json", core.canonical(expected))

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_confused_deputy_boundary(model: Any) -> ConfusedDeputyBoundary:
    """Project supplied authority decisions without invoking an operation."""
    return ConfusedDeputyBoundary(_derive(model))


def verify_supplied_confused_deputy_boundary(
    report: Any, *, model: Any
) -> ConfusedDeputyBoundary:
    if type(report) is not ConfusedDeputyBoundary:
        raise ConfusedDeputyBoundaryError("Exact native analysis wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise ConfusedDeputyBoundaryError("Report differs from supplied source replay")
    return ConfusedDeputyBoundary(expected)

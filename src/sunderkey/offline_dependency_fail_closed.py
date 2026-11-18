"""Project supplied dependency-failure fallback decisions without target use."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "supplied_dependency_fail_closed"
PROFILE_ID = "AOE-GE-D23-S12"
CAPABILITY_ID = "army.ge.d23.s12"
VECTOR_ID = "AV-GE-D23-S12-01"
WORK_PACKAGE_ID = "IWP2-AOE-GE-D23-S12"
WAVE_ID = "IW2-026"
COMMANDER_ID = "AOE-GE-D23-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:b88c05451baee1b56d3bf9602055bd44a5e2b8056918e755bba5e1c12e96f46b"
SEMANTICS_PROFILE = "supplied-dependency-failure-fallback-v1"
DOMAIN = "sunderkey.offline-dependency-fail-closed.v1"
MAX_SOURCE_BYTES = 32_768
MAX_REPORT_BYTES = 65_536
MAX_OBSERVATIONS = 128
_REF = re.compile(r"ref:[A-Za-z0-9][A-Za-z0-9._:-]{0,63}\Z")
_DEPENDENCY_STATES = {"available", "failed", "unknown"}
_DECISIONS = {"allow", "deny", "unknown"}
_EFFECTS = dict.fromkeys(
    (
        "authority", "credential", "execution", "filesystem", "network",
        "publication", "qualification", "target",
    ),
    "none",
)

DependencyFailClosedError = core.FrameworkDeclarationError


def _reference(value: Any) -> str:
    if type(value) is not str or _REF.fullmatch(value) is None:
        raise DependencyFailClosedError("Dependency must use an opaque reference")
    return value


def _model(value: Any) -> dict:
    core.validate_tree(value, maximum=MAX_SOURCE_BYTES)
    model = json.loads(core.canonical(value))
    item = core.exact(
        model,
        {"schema_version", "semantics_profile", "source_id", "policy", "observations"},
        "model",
    )
    if type(item["schema_version"]) is not int or item["schema_version"] != 1:
        raise DependencyFailClosedError("Schema version is invalid")
    if item["semantics_profile"] != SEMANTICS_PROFILE:
        raise DependencyFailClosedError("Semantics profile is invalid")
    core.identifier(item["source_id"], "source ID")
    policy = core.exact(
        item["policy"],
        {"declaration_complete", "deny_on_dependency_failure"},
        "policy",
    )
    core.boolean(policy["declaration_complete"], "policy completeness")
    core.boolean(policy["deny_on_dependency_failure"], "deny on dependency failure")
    observations = core.bounded_list(item["observations"], MAX_OBSERVATIONS, "observations")
    if not observations:
        raise DependencyFailClosedError("At least one observation is required")
    identifiers: set[str] = set()
    for raw in observations:
        observation = core.exact(
            raw,
            {
                "observation_id", "dependency_ref", "dependency_state",
                "configured_fallback", "declared_outcome", "capture_complete",
            },
            "observation",
        )
        identity = core.identifier(observation["observation_id"], "observation ID")
        if identity in identifiers:
            raise DependencyFailClosedError("Observation identifier is repeated")
        identifiers.add(identity)
        _reference(observation["dependency_ref"])
        core.choice(observation["dependency_state"], _DEPENDENCY_STATES, "dependency state")
        core.choice(observation["configured_fallback"], _DECISIONS, "configured fallback")
        core.choice(observation["declared_outcome"], _DECISIONS, "declared outcome")
        core.boolean(observation["capture_complete"], "capture completeness")
    return model


def _derive(value: Any) -> dict:
    model = _model(value)
    policy = model["policy"]
    projections = []
    for item in sorted(model["observations"], key=lambda row: row["observation_id"]):
        failed = item["dependency_state"] == "failed"
        negative = failed and policy["deny_on_dependency_failure"]
        if not policy["declaration_complete"] or not item["capture_complete"]:
            disposition = "unresolved_declaration_or_capture"
        elif (
            item["dependency_state"] == "unknown"
            or item["declared_outcome"] == "unknown"
            or (failed and item["configured_fallback"] == "unknown")
        ):
            disposition = "unresolved_decision_or_dependency"
        elif failed and item["configured_fallback"] != item["declared_outcome"]:
            disposition = "unresolved_fallback_outcome_mismatch"
        elif not negative:
            disposition = "no_declared_negative_invariant"
        elif item["declared_outcome"] == "allow":
            disposition = "candidate_declared_fail_open_conflict"
        else:
            disposition = "declared_deny_consistent"
        projections.append(
            {
                "observation_id": item["observation_id"],
                "negative_predicate": "dependency_failure_requires_deny" if negative else None,
                "disposition": disposition,
            }
        )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "source_model": model,
        "observation_count": len(projections),
        "projections": projections,
        "flags": {
            "dependency_failure_verified": False,
            "runtime_fallback_verified": False,
            "fail_open_behavior_verified": False,
            "positive_use_approved": False,
            "qualification_claimed": False,
        },
        "operational_effects": dict(_EFFECTS),
        "limitations": [
            "Dependency state, fallback policy and outcomes are caller assertions.",
            "A declared conflict does not verify a fail-open target path.",
            "A declared mismatch is unresolved, not proof of an alternate path.",
            "No file, credential, network, process or target is accessed.",
        ],
    }
    report_id, report_sha256 = core.report_address(
        body, domain=DOMAIN, prefix="DFC-"
    )
    report = {**body, "analysis_id": report_id, "analysis_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return json.loads(core.canonical(report))


@dataclass(frozen=True, slots=True, init=False)
class DependencyFailClosed:
    """Immutable replay of a supplied dependency-failure decision model."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        if type(document) is not dict or type(document.get("source_model")) is not dict:
            raise DependencyFailClosedError("Exact native report with source model required")
        expected = _derive(document["source_model"])
        core.validate_tree(document, maximum=MAX_REPORT_BYTES)
        if core.canonical(document) != core.canonical(expected):
            raise DependencyFailClosedError("Report differs from embedded source replay")
        object.__setattr__(self, "_document_json", core.canonical(expected))

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_dependency_fail_closed(model: Any) -> DependencyFailClosed:
    """Project supplied failure decisions without contacting a dependency."""
    return DependencyFailClosed(_derive(model))


def verify_supplied_dependency_fail_closed(
    report: Any, *, model: Any
) -> DependencyFailClosed:
    if type(report) is not DependencyFailClosed:
        raise DependencyFailClosedError("Exact native analysis wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise DependencyFailClosedError("Report differs from supplied source replay")
    return DependencyFailClosed(expected)

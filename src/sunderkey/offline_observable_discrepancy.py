"""Project supplied restricted observations against allowed field sets."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "supplied_observable_discrepancy"
PROFILE_ID = "AOE-GE-D23-S16"
CAPABILITY_ID = "army.ge.d23.s16"
VECTOR_ID = "AV-GE-D23-S16-01"
WORK_PACKAGE_ID = "IWP2-AOE-GE-D23-S16"
WAVE_ID = "IW2-030"
COMMANDER_ID = "AOE-GE-D23-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:639db9b1234ca25deb3dcc2cfeefac31d3eb24128deb0a413f33c71471715f6f"
SEMANTICS_PROFILE = "supplied-observable-field-discrepancy-v1"
DOMAIN = "sunderkey.offline-observable-discrepancy.v1"
MAX_SOURCE_BYTES = 32_768
MAX_REPORT_BYTES = 65_536
MAX_COMPARISONS = 64
MAX_FIELDS = 64
_REF = re.compile(r"ref:[A-Za-z0-9][A-Za-z0-9._:-]{0,63}\Z")
_EFFECTS = dict.fromkeys(
    ("authority", "credential", "execution", "filesystem", "network",
     "publication", "qualification", "target"),
    "none",
)

ObservableDiscrepancyError = core.FrameworkDeclarationError


def _reference(value: Any) -> str:
    if type(value) is not str or _REF.fullmatch(value) is None:
        raise ObservableDiscrepancyError("Field and resource labels must be opaque references")
    return value


def _references(value: Any, label: str) -> list[str]:
    entries = core.bounded_list(value, MAX_FIELDS, label)
    result = [_reference(item) for item in entries]
    if len(set(result)) != len(result):
        raise ObservableDiscrepancyError(f"{label} repeats a field reference")
    return result


def _model(value: Any) -> dict:
    core.validate_tree(value, maximum=MAX_SOURCE_BYTES)
    model = json.loads(core.canonical(value))
    item = core.exact(
        model,
        {"schema_version", "semantics_profile", "source_id", "policy", "comparisons"},
        "model",
    )
    if type(item["schema_version"]) is not int or item["schema_version"] != 1:
        raise ObservableDiscrepancyError("Schema version is invalid")
    if item["semantics_profile"] != SEMANTICS_PROFILE:
        raise ObservableDiscrepancyError("Semantics profile is invalid")
    core.identifier(item["source_id"], "source ID")
    policy = core.exact(
        item["policy"], {"declaration_complete", "sensitive_field_refs"}, "policy"
    )
    core.boolean(policy["declaration_complete"], "policy completeness")
    _references(policy["sensitive_field_refs"], "sensitive fields")
    comparisons = core.bounded_list(item["comparisons"], MAX_COMPARISONS, "comparisons")
    if not comparisons:
        raise ObservableDiscrepancyError("At least one comparison is required")
    identifiers: set[str] = set()
    for raw in comparisons:
        row = core.exact(
            raw,
            {"comparison_id", "resource_ref", "permitted_restricted_field_refs",
             "observed_restricted_field_refs", "capture_complete"},
            "comparison",
        )
        identity = core.identifier(row["comparison_id"], "comparison ID")
        if identity in identifiers:
            raise ObservableDiscrepancyError("Comparison identifier is repeated")
        identifiers.add(identity)
        _reference(row["resource_ref"])
        _references(row["permitted_restricted_field_refs"], "permitted fields")
        _references(row["observed_restricted_field_refs"], "observed fields")
        core.boolean(row["capture_complete"], "capture completeness")
    return model


def _derive(value: Any) -> dict:
    model = _model(value)
    sensitive = set(model["policy"]["sensitive_field_refs"])
    projections = []
    for item in sorted(model["comparisons"], key=lambda row: row["comparison_id"]):
        extra = set(item["observed_restricted_field_refs"]) - set(
            item["permitted_restricted_field_refs"]
        )
        marked = sorted(extra & sensitive)
        if not model["policy"]["declaration_complete"] or not item["capture_complete"]:
            disposition = "unresolved_declaration_or_capture"
        elif marked:
            disposition = "candidate_declared_sensitive_field_exposure"
        elif extra:
            disposition = "declared_observable_discrepancy_without_sensitive_marker"
        else:
            disposition = "declared_restricted_fields_consistent"
        projections.append(
            {"comparison_id": item["comparison_id"],
             "extra_field_refs": sorted(extra),
             "marked_sensitive_extra_field_refs": marked,
             "disposition": disposition}
        )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "source_model": model,
        "comparison_count": len(projections),
        "projections": projections,
        "flags": {
            "policy_verified": False,
            "observation_verified": False,
            "information_disclosure_verified": False,
            "positive_use_approved": False,
            "qualification_claimed": False,
        },
        "operational_effects": dict(_EFFECTS),
        "limitations": [
            "Field sensitivity, permission and observation are caller assertions.",
            "Field references are opaque labels and no content is parsed or retained.",
            "A declared discrepancy does not verify target information disclosure.",
            "No file, credential, network, process or target is accessed.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="OBD-")
    report = {**body, "analysis_id": report_id, "analysis_sha256": report_sha256}
    core.validate_tree(report, maximum=MAX_REPORT_BYTES)
    return json.loads(core.canonical(report))


@dataclass(frozen=True, slots=True, init=False)
class ObservableDiscrepancy:
    """Immutable replay of one supplied field-observation model."""

    _document_json: str

    def __init__(self, document: Any) -> None:
        if type(document) is not dict or type(document.get("source_model")) is not dict:
            raise ObservableDiscrepancyError("Exact native report with source model required")
        expected = _derive(document["source_model"])
        core.validate_tree(document, maximum=MAX_REPORT_BYTES)
        if core.canonical(document) != core.canonical(expected):
            raise ObservableDiscrepancyError("Report differs from embedded source replay")
        object.__setattr__(self, "_document_json", core.canonical(expected))

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_observable_discrepancy(model: Any) -> ObservableDiscrepancy:
    """Project supplied field sets without observing a target."""
    return ObservableDiscrepancy(_derive(model))


def verify_supplied_observable_discrepancy(
    report: Any, *, model: Any
) -> ObservableDiscrepancy:
    if type(report) is not ObservableDiscrepancy:
        raise ObservableDiscrepancyError("Exact native analysis wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise ObservableDiscrepancyError("Report differs from supplied source replay")
    return ObservableDiscrepancy(expected)

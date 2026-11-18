"""Reconcile synthetic organization-relationship claims without personal data."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "recon_supplied_organization_relationship_provenance"
PROFILE_ID = "AOE-GA-D01-S09"
CAPABILITY_ID = "army.ga.d01.s09"
VECTOR_ID = "AV-GA-D01-S09-01"
WORK_PACKAGE_ID = "IWP2-AOE-GA-D01-S09"
WAVE_ID = "IW2-009"
COMMANDER_ID = "AOE-GA-D01-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:8f7feb474c7e213da75688804a6c8a2fddb845d8b3e13ed1a7f1a78d76270da1"
DOMAIN = "sunderkey.offline-organization-relationship-provenance.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 262_144
MAX_RECORDS = 512
MAX_TICK = 1_000_000_000
SYNTHETIC_ID = re.compile(r"synthetic:[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
RELATIONSHIP_KINDS = {"employment", "contract", "representation"}
SOURCE_KINDS = {"public_profile", "organization_directory", "operator_assertion"}
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process", "provider",
        "credentials", "target_interaction", "finding_publication", "qualification",
    )
}


class OrganizationRelationshipProvenanceError(ValueError):
    """A supplied relationship model or separate-source replay is invalid."""


def _synthetic(value: Any, label: str) -> str:
    identifier = core.identifier(value, label)
    if SYNTHETIC_ID.fullmatch(identifier) is None:
        raise OrganizationRelationshipProvenanceError(f"{label} must be synthetic")
    return identifier


def _tick(value: Any, label: str) -> int:
    if type(value) is not int or not 0 <= value <= MAX_TICK:
        raise OrganizationRelationshipProvenanceError(f"{label} must be a bounded logical tick")
    return value


def _model(value: Any) -> dict:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {
            "schema_version", "source_id", "sources_complete", "policy_complete",
            "current_tick", "maximum_age_ticks", "records",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise OrganizationRelationshipProvenanceError("Unsupported model version")
    _synthetic(model["source_id"], "model source ID")
    core.boolean(model["sources_complete"], "source completeness")
    core.boolean(model["policy_complete"], "policy completeness")
    current = _tick(model["current_tick"], "current tick")
    _tick(model["maximum_age_ticks"], "maximum age")
    records = core.bounded_list(model["records"], MAX_RECORDS, "records")
    if not records:
        raise OrganizationRelationshipProvenanceError("At least one record is required")
    seen: set[str] = set()
    for item in records:
        row = core.exact(
            item,
            {
                "record_id", "subject_id", "organization_id", "relationship_kind",
                "source_ref", "source_kind", "observed_tick", "reported_state",
            },
            "record",
        )
        record_id = _synthetic(row["record_id"], "record ID")
        if record_id in seen:
            raise OrganizationRelationshipProvenanceError("Duplicate record ID")
        seen.add(record_id)
        for field in ("subject_id", "organization_id", "source_ref"):
            _synthetic(row[field], field)
        core.choice(row["relationship_kind"], RELATIONSHIP_KINDS, "relationship kind")
        core.choice(row["source_kind"], SOURCE_KINDS, "source kind")
        core.choice(row["reported_state"], {"current", "former"}, "reported state")
        if _tick(row["observed_tick"], "observed tick") > current:
            raise OrganizationRelationshipProvenanceError("Record is in supplied future")
    return model


def _derive(value: Any) -> dict:
    model = _model(value)
    grouped: dict[tuple[str, str, str], list[dict]] = {}
    for record in model["records"]:
        key = (
            record["subject_id"], record["organization_id"],
            record["relationship_kind"],
        )
        grouped.setdefault(key, []).append(record)
    complete = model["sources_complete"] and model["policy_complete"]
    projections: list[dict] = []
    for key in sorted(grouped):
        rows = grouped[key]
        fresh = [
            row for row in rows
            if model["current_tick"] - row["observed_tick"] <= model["maximum_age_ticks"]
        ]
        latest_tick_by_source: dict[str, int] = {}
        for row in fresh:
            source_ref = row["source_ref"]
            latest_tick_by_source[source_ref] = max(
                latest_tick_by_source.get(source_ref, -1), row["observed_tick"]
            )
        selected = [
            row for row in fresh
            if row["observed_tick"] == latest_tick_by_source[row["source_ref"]]
        ]
        selected_ids = {row["record_id"] for row in selected}
        current_sources = {
            row["source_ref"] for row in selected if row["reported_state"] == "current"
        }
        former_sources = {
            row["source_ref"] for row in selected if row["reported_state"] == "former"
        }
        if not complete:
            disposition = "unknown_incomplete_sources_or_policy"
        elif not fresh:
            disposition = "unknown_only_stale_claims"
        elif current_sources and former_sources:
            disposition = "candidate_conflicting_supplied_relationship_claims"
        elif len(current_sources) >= 2:
            disposition = "multiple_supplied_current_sources"
        elif current_sources:
            disposition = "single_supplied_current_source"
        else:
            disposition = "supplied_former_not_exclusion"
        projections.append({
            "subject_id": key[0],
            "organization_id": key[1],
            "relationship_kind": key[2],
            "fresh_record_ids": sorted(row["record_id"] for row in fresh),
            "superseded_fresh_record_ids": sorted(
                row["record_id"] for row in fresh if row["record_id"] not in selected_ids
            ),
            "stale_record_ids": sorted(row["record_id"] for row in rows if row not in fresh),
            "current_source_refs": sorted(current_sources),
            "former_source_refs": sorted(former_sources),
            "disposition": disposition,
        })
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model": model,
        "source_model_sha256": core.digest(core.canonical(model).encode("ascii")),
        "projections": projections,
        "summary": {
            "relationship_count": len(projections),
            "conflict_candidate_count": sum(
                row["disposition"] == "candidate_conflicting_supplied_relationship_claims"
                for row in projections
            ),
            "unknown_count": sum(
                row["disposition"].startswith("unknown_") for row in projections
            ),
        },
        "source_authenticated": False,
        "source_independence_proven": False,
        "person_identity_verified": False,
        "relationship_verified": False,
        "personal_data_processed": False,
        "public_collection_performed": False,
        "target_interaction_performed": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "All relationship, source, tick, completeness and age claims are supplied.",
            "Synthetic subject labels are not proof of real identity or affiliation.",
            "Distinct source references do not prove independent sources.",
            "No names, contacts, titles, profiles, pretexts or live sources are processed.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="ORP-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class OrganizationRelationshipProvenanceReport:
    """Unsigned relationship projection requiring separate original replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise OrganizationRelationshipProvenanceError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> OrganizationRelationshipProvenanceReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_organization_relationships(
    model: Any,
) -> OrganizationRelationshipProvenanceReport:
    try:
        return OrganizationRelationshipProvenanceReport._owned(_derive(model))
    except core.FrameworkDeclarationError as exc:
        raise OrganizationRelationshipProvenanceError(str(exc)) from exc


def verify_supplied_organization_relationships(
    report: Any, *, model: Any,
) -> OrganizationRelationshipProvenanceReport:
    if type(report) is not OrganizationRelationshipProvenanceReport:
        raise OrganizationRelationshipProvenanceError("Exact report wrapper required")
    expected = analyze_supplied_organization_relationships(model)
    if report.to_json() != expected.to_json():
        raise OrganizationRelationshipProvenanceError("Report differs from separate original model")
    return expected


def verify_supplied_organization_relationships_bytes(
    report_bytes: bytes, *, model: Any,
) -> OrganizationRelationshipProvenanceReport:
    try:
        report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    except core.FrameworkDeclarationError as exc:
        raise OrganizationRelationshipProvenanceError(str(exc)) from exc
    expected = analyze_supplied_organization_relationships(model)
    if type(report) is not dict or core.canonical(report) != expected.to_json():
        raise OrganizationRelationshipProvenanceError(
            "Exported report differs from original replay"
        )
    return expected


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic:organization-relationships",
        "sources_complete": True,
        "policy_complete": True,
        "current_tick": 100,
        "maximum_age_ticks": 20,
        "records": [
            {"record_id": "synthetic:current", "subject_id": "synthetic:subject-one",
             "organization_id": "synthetic:organization-one", "relationship_kind": "contract",
             "source_ref": "synthetic:source-one", "source_kind": "public_profile",
             "observed_tick": 90, "reported_state": "current"},
            {"record_id": "synthetic:former", "subject_id": "synthetic:subject-one",
             "organization_id": "synthetic:organization-one", "relationship_kind": "contract",
             "source_ref": "synthetic:source-two", "source_kind": "organization_directory",
             "observed_tick": 95, "reported_state": "former"},
            {"record_id": "synthetic:old", "subject_id": "synthetic:subject-two",
             "organization_id": "synthetic:organization-one", "relationship_kind": "employment",
             "source_ref": "synthetic:source-three", "source_kind": "operator_assertion",
             "observed_tick": 50, "reported_state": "current"},
        ],
    }


__all__ = [
    "OrganizationRelationshipProvenanceError", "OrganizationRelationshipProvenanceReport",
    "analyze_supplied_organization_relationships",
    "verify_supplied_organization_relationships",
    "verify_supplied_organization_relationships_bytes", "component_fixture",
]

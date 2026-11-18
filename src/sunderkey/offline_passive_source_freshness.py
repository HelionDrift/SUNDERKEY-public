"""Reconcile supplied passive source claims using logical freshness only."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "recon_supplied_passive_source_freshness"
PROFILE_ID = "AOE-GA-D01-S01"
CAPABILITY_ID = "army.ga.d01.s01"
VECTOR_ID = "AV-GA-D01-S01-01"
WORK_PACKAGE_ID = "IWP2-AOE-GA-D01-S01"
WAVE_ID = "IW2-001"
COMMANDER_ID = "AOE-GA-D01-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:a5a66609b1ce38c3eda866d62be0fef89711f0d5aa7470ca9f24323f5c2ec09b"
DOMAIN = "sunderkey.offline-passive-source-freshness.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 262_144
MAX_OBSERVATIONS = 512
MAX_TICK = 1_000_000_000
SYNTHETIC_ID = re.compile(r"synthetic:[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
SOURCE_KINDS = {"inventory_snapshot", "certificate_index", "archive_index", "operator_assertion"}
EFFECTS = {
    key: "none"
    for key in (
        "authority", "execution", "filesystem", "network", "process", "provider",
        "credentials", "target_interaction", "finding_publication", "qualification",
    )
}


class PassiveSourceFreshnessError(ValueError):
    """A supplied passive-source model or separate-source replay is invalid."""


def _synthetic(value: Any, label: str) -> str:
    identifier = core.identifier(value, label)
    if SYNTHETIC_ID.fullmatch(identifier) is None:
        raise PassiveSourceFreshnessError(f"{label} must be a synthetic label")
    return identifier


def _tick(value: Any, label: str) -> int:
    if type(value) is not int or not 0 <= value <= MAX_TICK:
        raise PassiveSourceFreshnessError(f"{label} must be a bounded logical tick")
    return value


def _model(value: Any) -> dict:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {
            "schema_version", "source_id", "sources_complete", "policy_complete",
            "current_tick", "maximum_age_ticks", "observations",
        },
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise PassiveSourceFreshnessError("Unsupported model version")
    _synthetic(model["source_id"], "model source ID")
    core.boolean(model["sources_complete"], "source completeness")
    core.boolean(model["policy_complete"], "policy completeness")
    current = _tick(model["current_tick"], "current tick")
    _tick(model["maximum_age_ticks"], "maximum age")
    observations = core.bounded_list(model["observations"], MAX_OBSERVATIONS, "observations")
    if not observations:
        raise PassiveSourceFreshnessError("At least one observation is required")
    seen: set[str] = set()
    for item in observations:
        row = core.exact(
            item,
            {
                "observation_id", "asset_id", "source_ref", "source_kind",
                "observed_tick", "claim",
            },
            "observation",
        )
        observation_id = _synthetic(row["observation_id"], "observation ID")
        if observation_id in seen:
            raise PassiveSourceFreshnessError("Duplicate observation ID")
        seen.add(observation_id)
        _synthetic(row["asset_id"], "asset ID")
        _synthetic(row["source_ref"], "source reference")
        core.choice(row["source_kind"], SOURCE_KINDS, "source kind")
        if _tick(row["observed_tick"], "observation tick") > current:
            raise PassiveSourceFreshnessError("Observation cannot be in the supplied future")
        core.choice(row["claim"], {"present", "absent"}, "claim")
    return model


def _derive(value: Any) -> dict:
    model = _model(value)
    by_asset: dict[str, list[dict]] = {}
    for observation in model["observations"]:
        by_asset.setdefault(observation["asset_id"], []).append(observation)
    complete = model["policy_complete"] and model["sources_complete"]
    projections: list[dict] = []
    for asset_id in sorted(by_asset):
        rows = by_asset[asset_id]
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
        selected_ids = {row["observation_id"] for row in selected}
        present = {row["source_ref"] for row in selected if row["claim"] == "present"}
        absent = {row["source_ref"] for row in selected if row["claim"] == "absent"}
        if not complete:
            disposition = "unknown_incomplete_sources_or_policy"
        elif not fresh:
            disposition = "unknown_only_stale_claims"
        elif present and absent:
            disposition = "candidate_conflicting_supplied_claims"
        elif len(present) >= 2:
            disposition = "multiple_supplied_presence_sources"
        elif present:
            disposition = "single_supplied_presence_source"
        else:
            disposition = "supplied_absence_not_exclusion"
        projections.append({
            "asset_id": asset_id,
            "fresh_observation_ids": sorted(row["observation_id"] for row in fresh),
            "superseded_fresh_observation_ids": sorted(
                row["observation_id"] for row in fresh
                if row["observation_id"] not in selected_ids
            ),
            "stale_observation_ids": sorted(
                row["observation_id"] for row in rows if row not in fresh
            ),
            "fresh_present_source_refs": sorted(present),
            "fresh_absent_source_refs": sorted(absent),
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
            "asset_count": len(projections),
            "conflict_candidate_count": sum(
                row["disposition"] == "candidate_conflicting_supplied_claims"
                for row in projections
            ),
            "unknown_count": sum(
                row["disposition"].startswith("unknown_") for row in projections
            ),
        },
        "source_authenticated": False,
        "source_independence_proven": False,
        "wall_clock_freshness_verified": False,
        "asset_ownership_verified": False,
        "passive_collection_performed": False,
        "active_scan_performed": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Source references, claims, ticks and age policy are caller declarations.",
            "Distinct source references do not prove independent or trustworthy sources.",
            "Logical freshness does not prove wall-clock recency, ownership or exposure.",
            "No public source, network endpoint, provider, repository or target is queried.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="PSF-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class PassiveSourceFreshnessReport:
    """Unsigned passive-source projection requiring separate original replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise PassiveSourceFreshnessError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> PassiveSourceFreshnessReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_passive_sources(model: Any) -> PassiveSourceFreshnessReport:
    try:
        return PassiveSourceFreshnessReport._owned(_derive(model))
    except core.FrameworkDeclarationError as exc:
        raise PassiveSourceFreshnessError(str(exc)) from exc


def verify_supplied_passive_sources(
    report: Any, *, model: Any,
) -> PassiveSourceFreshnessReport:
    if type(report) is not PassiveSourceFreshnessReport:
        raise PassiveSourceFreshnessError("Exact report wrapper required")
    expected = analyze_supplied_passive_sources(model)
    if report.to_json() != expected.to_json():
        raise PassiveSourceFreshnessError("Report differs from separate original model")
    return expected


def verify_supplied_passive_sources_bytes(
    report_bytes: bytes, *, model: Any,
) -> PassiveSourceFreshnessReport:
    try:
        report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    except core.FrameworkDeclarationError as exc:
        raise PassiveSourceFreshnessError(str(exc)) from exc
    expected = analyze_supplied_passive_sources(model)
    if type(report) is not dict or core.canonical(report) != expected.to_json():
        raise PassiveSourceFreshnessError("Exported report differs from original replay")
    return expected


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic:passive-sources",
        "sources_complete": True,
        "policy_complete": True,
        "current_tick": 100,
        "maximum_age_ticks": 20,
        "observations": [
            {"observation_id": "synthetic:present", "asset_id": "synthetic:asset-one",
             "source_ref": "synthetic:archive", "source_kind": "archive_index",
             "observed_tick": 90, "claim": "present"},
            {"observation_id": "synthetic:absent", "asset_id": "synthetic:asset-one",
             "source_ref": "synthetic:inventory", "source_kind": "inventory_snapshot",
             "observed_tick": 95, "claim": "absent"},
            {"observation_id": "synthetic:stale", "asset_id": "synthetic:asset-two",
             "source_ref": "synthetic:old-index", "source_kind": "certificate_index",
             "observed_tick": 50, "claim": "present"},
        ],
    }


__all__ = [
    "PassiveSourceFreshnessError", "PassiveSourceFreshnessReport",
    "analyze_supplied_passive_sources", "verify_supplied_passive_sources",
    "verify_supplied_passive_sources_bytes", "component_fixture",
]

"""Compare supplied synthetic macOS release metadata with a declared baseline."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "macos_supplied_release_metadata_consistency"
PROFILE_ID = "AOE-GB-D08-S16"
CAPABILITY_ID = "army.gb.d08.s16"
VECTOR_ID = "AV-GB-D08-S16-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D08-S16"
WAVE_ID = "IW2-002"
COMMANDER_ID = "AOE-GB-D08-CMD"
GROUP_OWNER_ID = "AOE-HQ-04"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:651f8f01758fd3fd2633899d62e3eef0493e5f02f737a24f735787a797cf5916"
DOMAIN = "sunderkey.offline-macos-release-metadata.v1"
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class MacosReleaseMetadataError(ValueError):
    """The declaration or original-model replay is invalid."""


def _ids(value: Any, maximum: int, label: str) -> set[str]:
    items = [core.identifier(item, label) for item in core.bounded_list(value, maximum, label)]
    if len(items) != len(set(items)):
        raise MacosReleaseMetadataError(f"Duplicate {label}")
    return set(items)


def _build(value: Any) -> int:
    if type(value) is not int or not 0 <= value <= 2_147_483_647:
        raise MacosReleaseMetadataError("Build must be a bounded nonnegative integer")
    return value


def _derive(value: Any) -> dict:
    core.validate_tree(value, maximum=131_072)
    model = core.exact(json.loads(core.canonical(value)), {
        "schema_version", "source_id", "synthetic_fixture", "inventory_complete",
        "baseline", "releases",
    }, "model")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise MacosReleaseMetadataError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if not core.boolean(model["synthetic_fixture"], "synthetic fixture"):
        raise MacosReleaseMetadataError("Only synthetic fixtures are accepted")
    complete = core.boolean(model["inventory_complete"], "inventory completeness")
    baseline = core.exact(model["baseline"], {
        "bundle_id", "team_id", "minimum_build", "required_entitlement_ids",
        "allowed_entitlement_ids",
    }, "baseline")
    bundle_id = core.identifier(baseline["bundle_id"], "bundle ID")
    team_id = core.identifier(baseline["team_id"], "team ID")
    minimum = _build(baseline["minimum_build"])
    required = _ids(baseline["required_entitlement_ids"], 32, "required entitlement ID")
    allowed = _ids(baseline["allowed_entitlement_ids"], 32, "allowed entitlement ID")
    if not required.issubset(allowed):
        raise MacosReleaseMetadataError("Required entitlements must be allowed")
    rows = []
    seen = set()
    for item in core.bounded_list(model["releases"], 64, "releases"):
        row = core.exact(item, {
            "release_id", "bundle_id", "team_id", "build", "entitlement_ids",
        }, "release")
        release_id = core.identifier(row["release_id"], "release ID")
        if release_id in seen:
            raise MacosReleaseMetadataError("Duplicate release ID")
        seen.add(release_id)
        actual = _ids(row["entitlement_ids"], 32, "release entitlement ID")
        release_bundle = core.identifier(row["bundle_id"], "release bundle ID")
        release_team = core.identifier(row["team_id"], "release team ID")
        build = _build(row["build"])
        flags = []
        if release_bundle != bundle_id:
            flags.append("bundle_differs_from_baseline")
        if release_team != team_id:
            flags.append("team_differs_from_baseline")
        if build < minimum:
            flags.append("build_below_declared_minimum")
        rows.append({
            "release_id": release_id,
            "declared_consistency_flags": sorted(flags),
            "missing_required_entitlement_ids": sorted(required - actual),
            "unexpected_entitlement_ids": sorted(actual - allowed),
        })
    if not rows:
        raise MacosReleaseMetadataError("At least one release is required")
    rows.sort(key=lambda row: row["release_id"])
    changed = sorted(
        row["release_id"] for row in rows
        if row["declared_consistency_flags"]
        or row["missing_required_entitlement_ids"]
        or row["unexpected_entitlement_ids"]
    )
    unknown = [] if complete else ["supplied_release_inventory_incomplete"]
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "capability_id": CAPABILITY_ID,
        "vector_id": VECTOR_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "wave_id": WAVE_ID,
        "commander_id": COMMANDER_ID,
        "group_owner_id": GROUP_OWNER_ID,
        "independent_validator_id": INDEPENDENT_VALIDATOR_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(core.canonical(model).encode("ascii")),
        "synthetic_fixture_asserted": True,
        "inventory_complete_asserted": complete,
        "supplied_release_count": len(rows),
        "release_projections": rows,
        "baseline_deviation_release_ids": changed,
        "candidate_count": 0,
        "uncertainty": unknown,
        "unknown_count": len(unknown),
        "disposition": "unknown" if unknown else "supplied_release_metadata_projection",
        "source_authenticated": False,
        "application_inspected": False,
        "signature_verified": False,
        "entitlement_effect_verified": False,
        "platform_policy_verified": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Release metadata and the baseline are supplied assertions.",
            "A metadata difference does not prove a signing, entitlement, or policy weakness.",
            "No package, certificate, macOS host, application, or target is inspected.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="MRM-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=131_072)
    return report


@dataclass(frozen=True, slots=True, init=False)
class MacosReleaseMetadataReport:
    """Unsigned projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise MacosReleaseMetadataError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> MacosReleaseMetadataReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_macos_releases(model: Any) -> MacosReleaseMetadataReport:
    return MacosReleaseMetadataReport._owned(_derive(model))


def verify_supplied_macos_releases(
    report: Any, *, model: Any
) -> MacosReleaseMetadataReport:
    if type(report) is not MacosReleaseMetadataReport:
        raise MacosReleaseMetadataError("Exact release wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise MacosReleaseMetadataError("Report differs from separate original model")
    return MacosReleaseMetadataReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1, "source_id": "synthetic-macos-release",
        "synthetic_fixture": True, "inventory_complete": True,
        "baseline": {
            "bundle_id": "com.example.app", "team_id": "TEAM123",
            "minimum_build": 20,
            "required_entitlement_ids": ["sandbox"],
            "allowed_entitlement_ids": ["sandbox", "network-client"],
        },
        "releases": [{
            "release_id": "r21", "bundle_id": "com.example.app",
            "team_id": "TEAM123", "build": 21,
            "entitlement_ids": ["sandbox", "network-client"],
        }],
    }

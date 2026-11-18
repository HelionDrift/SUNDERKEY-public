"""Project supplied synthetic managed mobile app release assignments."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "mobile_supplied_distribution_consistency_projection"
PROFILE_ID = "AOE-GB-D08-S14"
CAPABILITY_ID = "army.gb.d08.s14"
VECTOR_ID = "AV-GB-D08-S14-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D08-S14"
WAVE_ID = "IW2-018"
COMMANDER_ID = "AOE-GB-D08-CMD"
GROUP_OWNER_ID = "AOE-HQ-04"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:721ad8ea5a36987477f75e76f460e523b03a9ba3d361a0f59c2e754ac1c1733c"
DOMAIN = "sunderkey.offline-mobile-distribution.v1"
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
EFFECTS = {key: "none" for key in (
    "authority", "execution", "filesystem", "network", "process", "provider",
    "credentials", "target_interaction", "finding_publication", "qualification",
)}


class MobileDistributionError(ValueError):
    """The declaration or original-model replay is invalid."""


def _digest(value: Any, label: str) -> str:
    if type(value) is not str or DIGEST.fullmatch(value) is None:
        raise MobileDistributionError(f"{label} must be lowercase SHA-256 hex")
    return value


def _build(value: Any, label: str) -> int:
    if type(value) is not int or not 0 <= value <= 2_147_483_647:
        raise MobileDistributionError(f"{label} must be a bounded nonnegative build number")
    return value


def _derive(value: Any) -> dict:
    core.validate_tree(value, maximum=131_072)
    model = core.exact(json.loads(core.canonical(value)), {
        "schema_version", "source_id", "synthetic_fixture", "inventory_complete",
        "channels", "releases", "assignments",
    }, "model")
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise MobileDistributionError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    if not core.boolean(model["synthetic_fixture"], "synthetic fixture"):
        raise MobileDistributionError("Only synthetic fixtures are accepted")
    complete = core.boolean(model["inventory_complete"], "inventory completeness")
    channels = {}
    for item in core.bounded_list(model["channels"], 32, "channels"):
        row = core.exact(item, {
            "channel_id", "minimum_build", "expected_signer_sha256_hex",
        }, "channel")
        channel_id = core.identifier(row["channel_id"], "channel ID")
        if channel_id in channels:
            raise MobileDistributionError("Duplicate channel ID")
        channels[channel_id] = (
            _build(row["minimum_build"], "minimum build"),
            _digest(row["expected_signer_sha256_hex"], "expected signer"),
        )
    if not channels:
        raise MobileDistributionError("At least one channel is required")
    releases = {}
    for item in core.bounded_list(model["releases"], 64, "releases"):
        row = core.exact(item, {
            "release_id", "channel_id", "build", "signer_sha256_hex",
        }, "release")
        release_id = core.identifier(row["release_id"], "release ID")
        channel_id = core.identifier(row["channel_id"], "channel ID")
        if release_id in releases or channel_id not in channels:
            raise MobileDistributionError("Duplicate release ID or unknown channel")
        releases[release_id] = (
            channel_id, _build(row["build"], "release build"),
            _digest(row["signer_sha256_hex"], "release signer"),
        )
    if not releases:
        raise MobileDistributionError("At least one release is required")
    rows = []
    seen = set()
    for item in core.bounded_list(model["assignments"], 64, "assignments"):
        row = core.exact(item, {"cohort_id", "channel_id", "release_id"}, "assignment")
        cohort_id = core.identifier(row["cohort_id"], "cohort ID")
        channel_id = core.identifier(row["channel_id"], "channel ID")
        release_id = core.identifier(row["release_id"], "release ID")
        if cohort_id in seen:
            raise MobileDistributionError("Duplicate cohort ID")
        seen.add(cohort_id)
        if channel_id not in channels:
            raise MobileDistributionError("Unknown assignment channel")
        flags = []
        if release_id not in releases:
            flags.append("release_not_supplied")
        else:
            release_channel, build, signer = releases[release_id]
            minimum, expected_signer = channels[channel_id]
            if release_channel != channel_id:
                flags.append("release_channel_mismatch")
            if build < minimum:
                flags.append("build_below_declared_minimum")
            if signer != expected_signer:
                flags.append("signer_differs_from_declared_channel")
        rows.append({
            "cohort_id": cohort_id, "channel_id": channel_id,
            "release_id": release_id, "declared_consistency_flags": sorted(flags),
        })
    if not rows:
        raise MobileDistributionError("At least one assignment is required")
    rows.sort(key=lambda row: row["cohort_id"])
    unknown = [] if complete else ["supplied_distribution_inventory_incomplete"]
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
        "supplied_channel_count": len(channels),
        "supplied_release_count": len(releases),
        "supplied_assignment_count": len(rows),
        "assignment_projections": rows,
        "inconsistent_cohort_ids": sorted(
            row["cohort_id"] for row in rows if row["declared_consistency_flags"]
        ),
        "candidate_count": 0,
        "uncertainty": unknown,
        "unknown_count": len(unknown),
        "disposition": "unknown" if unknown else "supplied_distribution_consistency_projection",
        "source_authenticated": False,
        "package_inspected": False,
        "signature_verified": False,
        "mdm_state_verified": False,
        "device_inspected": False,
        "target_interacted": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Channels, releases, signers, builds, and assignments are supplied assertions.",
            "A mismatch with declared metadata is not proof of an MDM or app vulnerability.",
            "No package, signing certificate, device, MDM service, or target is accessed.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="MDP-")
    report = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(report, maximum=131_072)
    return report


@dataclass(frozen=True, slots=True, init=False)
class MobileDistributionReport:
    """Unsigned projection requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise MobileDistributionError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> MobileDistributionReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_mobile_distribution(model: Any) -> MobileDistributionReport:
    return MobileDistributionReport._owned(_derive(model))


def verify_supplied_mobile_distribution(
    report: Any, *, model: Any
) -> MobileDistributionReport:
    if type(report) is not MobileDistributionReport:
        raise MobileDistributionError("Exact distribution wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise MobileDistributionError("Report differs from separate original model")
    return MobileDistributionReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1, "source_id": "synthetic-mobile-distribution",
        "synthetic_fixture": True, "inventory_complete": True,
        "channels": [{
            "channel_id": "managed", "minimum_build": 20,
            "expected_signer_sha256_hex": "a" * 64,
        }],
        "releases": [{
            "release_id": "r21", "channel_id": "managed", "build": 21,
            "signer_sha256_hex": "a" * 64,
        }],
        "assignments": [{
            "cohort_id": "pilot", "channel_id": "managed", "release_id": "r21",
        }],
    }

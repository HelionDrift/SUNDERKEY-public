"""Validation for the parallel Army v1 to v2 registry migration."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .army_expansion import ArmyExpansionRoadmap
from .errors import RegistryError
from .qualification import _canonical_sha256
from .registry import ExpertRegistry, load_registry

REPORT_DOMAIN = "sunderkey.army-v2-migration-report.v1"
TARGET_CATALOG_ID = "sunderkey-offensive-expert-army"
TARGET_CATALOG_VERSION = "2.0.0"


@dataclass(frozen=True)
class ArmyV2MigrationReport:
    """Read-only proof that Army v2 is additive and remains inactive."""

    report_id: str
    report_sha256: str
    source_catalog_id: str
    source_catalog_version: str
    target_catalog_id: str
    target_catalog_version: str
    preserved_profile_count: int
    added_specialist_count: int
    added_commander_count: int
    added_shared_profile_count: int
    target_profile_count: int
    target_command_count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_id": self.report_id,
            "report_sha256": self.report_sha256,
            "source_catalog_id": self.source_catalog_id,
            "source_catalog_version": self.source_catalog_version,
            "target_catalog_id": self.target_catalog_id,
            "target_catalog_version": self.target_catalog_version,
            "preserved_profile_count": self.preserved_profile_count,
            "added_specialist_count": self.added_specialist_count,
            "added_commander_count": self.added_commander_count,
            "added_shared_profile_count": self.added_shared_profile_count,
            "target_profile_count": self.target_profile_count,
            "target_command_count": self.target_command_count,
            "migration_status": "valid_additive_parallel_catalog",
            "new_profile_status": "defined_inactive",
            "qualification_effect": "none",
            "routing_effect": "none",
            "execution_effect": "none",
            "deployment_effect": "none",
        }


def _migration_body(
    baseline: ExpertRegistry,
    target: ExpertRegistry,
    roadmap: ArmyExpansionRoadmap,
) -> dict[str, Any]:
    return {
        "source_catalog_id": baseline.catalog_id,
        "source_catalog_version": baseline.catalog_version,
        "source_registry_sha256": _canonical_sha256(baseline.to_dict()),
        "target_catalog_id": target.catalog_id,
        "target_catalog_version": target.catalog_version,
        "target_registry_sha256": _canonical_sha256(target.to_dict()),
        "roadmap_id": roadmap.roadmap_id,
        "roadmap_sha256": roadmap.roadmap_sha256,
        "preserved_profile_count": len(baseline.profiles),
        "added_specialist_count": roadmap.delta_counts["specialists"],
        "added_commander_count": roadmap.delta_counts["domain_commanders"],
        "added_shared_profile_count": roadmap.delta_counts["shared_profiles"],
        "target_profile_count": len(target.profiles),
        "target_command_count": len(target.commands),
        "migration_status": "valid_additive_parallel_catalog",
        "new_profile_status": "defined_inactive",
        "qualification_effect": "none",
        "routing_effect": "none",
        "execution_effect": "none",
        "deployment_effect": "none",
    }


def validate_army_v2_migration(
    baseline: ExpertRegistry,
    target: ExpertRegistry,
    roadmap: ArmyExpansionRoadmap,
) -> ArmyV2MigrationReport:
    """Fail closed unless target is the exact approved, additive Army v2 shape."""

    if baseline.catalog_version != "1.0.0":
        raise RegistryError("Army v2 migration requires the version 1.0.0 baseline")
    if target.catalog_id != TARGET_CATALOG_ID or target.catalog_version != TARGET_CATALOG_VERSION:
        raise RegistryError("Army v2 target catalog identity is invalid")
    if target.schema_version != baseline.schema_version:
        raise RegistryError("Army v2 must retain the supported registry schema version")
    if target.policies != baseline.policies:
        raise RegistryError("Army v2 policy templates must preserve the v1 definitions")

    baseline_profiles = baseline.to_dict()["profiles"]
    target_profiles = target.to_dict()["profiles"]
    if target_profiles[: len(baseline_profiles)] != baseline_profiles:
        raise RegistryError("Army v2 must preserve every v1 profile without mutation")

    baseline_commands = baseline.to_dict()["commands"]
    target_commands = target.to_dict()["commands"]
    target_commands_by_id = {item["id"]: item for item in target_commands}
    approved_existing = {
        item["command_id"]: [profile["profile_id"] for profile in item["specialists"]]
        for item in roadmap.existing_command_additions
    }
    for source in baseline_commands:
        candidate = target_commands_by_id.get(source["id"])
        if candidate is None:
            raise RegistryError(f"Army v2 removed v1 command {source['id']}")
        expected = dict(source)
        expected["specialist_profile_ids"] = [
            *source["specialist_profile_ids"],
            *approved_existing.get(source["id"], []),
        ]
        if candidate != expected:
            raise RegistryError(f"Army v2 changed v1 command {source['id']} beyond D015")

    baseline_groups = baseline.to_dict()["groups"]
    target_groups_by_id = {item["id"]: item for item in target.to_dict()["groups"]}
    target_specialists = {
        item["group_id"]: item["target_specialists"] for item in roadmap.to_dict()["group_targets"]
    }
    for source in baseline_groups:
        expected = dict(source)
        expected["specialist_count"] = target_specialists[source["id"]]
        if source["id"] == "GD":
            expected["command_ids"] = [*source["command_ids"], "AOE-GD-D24", "AOE-GD-D25"]
        if target_groups_by_id.get(source["id"]) != expected:
            raise RegistryError(f"Army v2 group {source['id']} does not match D015")

    expected_new_command_ids = tuple(item["command_id"] for item in roadmap.new_commands)
    if (
        tuple(item["id"] for item in target_commands[len(baseline_commands) :])
        != expected_new_command_ids
    ):
        raise RegistryError("Army v2 new commands do not match D015")

    expected_new_ids = {
        profile["profile_id"]
        for command in (
            *roadmap.existing_command_additions,
            *roadmap.new_commands,
        )
        for profile in command["specialists"]
    }
    expected_new_ids.update(item["commander_profile_id"] for item in roadmap.new_commands)
    expected_new_ids.update(item["profile_id"] for item in roadmap.shared_profile_additions)
    additions = target_profiles[len(baseline_profiles) :]
    if {item["id"] for item in additions} != expected_new_ids or len(additions) != 48:
        raise RegistryError("Army v2 profile additions do not match D015")
    for profile in additions:
        if profile["status"] != "defined" or profile["pilot"] is not False:
            raise RegistryError(f"Army v2 profile {profile['id']} is not defined and inactive")
        if "qualification" in profile:
            raise RegistryError(f"Army v2 profile {profile['id']} cannot carry qualification")

    if target.count_contract.to_dict() != roadmap.target_counts:
        raise RegistryError("Army v2 count contract does not match D015")

    body = _migration_body(baseline, target, roadmap)
    digest = _canonical_sha256({"domain": REPORT_DOMAIN, "report": body})
    return ArmyV2MigrationReport(
        report_id=f"AVM-{digest.removeprefix('sha256:')[:32].upper()}",
        report_sha256=digest,
        source_catalog_id=baseline.catalog_id,
        source_catalog_version=baseline.catalog_version,
        target_catalog_id=target.catalog_id,
        target_catalog_version=target.catalog_version,
        preserved_profile_count=len(baseline.profiles),
        added_specialist_count=roadmap.delta_counts["specialists"],
        added_commander_count=roadmap.delta_counts["domain_commanders"],
        added_shared_profile_count=roadmap.delta_counts["shared_profiles"],
        target_profile_count=len(target.profiles),
        target_command_count=len(target.commands),
    )


def load_and_validate_army_v2_migration(
    baseline_path: str | Path,
    target_path: str | Path,
    roadmap: ArmyExpansionRoadmap,
) -> tuple[ExpertRegistry, ArmyV2MigrationReport]:
    baseline = load_registry(baseline_path)
    target = load_registry(target_path)
    return target, validate_army_v2_migration(baseline, target, roadmap)


def migration_report_json(report: ArmyV2MigrationReport) -> str:
    return json.dumps(report.to_dict(), sort_keys=True, separators=(",", ":"))


__all__ = [
    "ArmyV2MigrationReport",
    "load_and_validate_army_v2_migration",
    "migration_report_json",
    "validate_army_v2_migration",
]

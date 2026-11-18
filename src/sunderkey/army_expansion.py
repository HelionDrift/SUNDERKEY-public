"""Strict, content-addressed Army v2 expansion roadmap contracts."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import SunderkeyError
from .qualification import _canonical_json, _canonical_sha256, _exact_fields, _mapping

SCHEMA_VERSION = 1
ROADMAP_DOMAIN = "sunderkey.army-expansion-roadmap.v1"
ROADMAP_ID_PATTERN = re.compile(r"AER-[0-9A-F]{32}")
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
PROFILE_ID_PATTERN = re.compile(r"AOE-(?:G[A-E]-D[0-9]{2}-(?:CMD|S[0-9]{2})|HQ-[0-9]{2})")
COMMAND_ID_PATTERN = re.compile(r"AOE-G[A-E]-D[0-9]{2}")
PHASE_ID_PATTERN = re.compile(r"Phase[0-9]{3}")

BASELINE_COUNTS = {
    "groups": 5,
    "commands": 23,
    "specialists": 348,
    "domain_commanders": 23,
    "shared_profiles": 32,
    "total_profiles": 403,
    "pilot_specialists": 20,
}
TARGET_COUNTS = {
    "groups": 5,
    "commands": 25,
    "specialists": 391,
    "domain_commanders": 25,
    "shared_profiles": 35,
    "total_profiles": 451,
    "pilot_specialists": 20,
}
DELTA_COUNTS = {
    "groups": 0,
    "commands": 2,
    "specialists": 43,
    "domain_commanders": 2,
    "shared_profiles": 3,
    "total_profiles": 48,
    "pilot_specialists": 0,
}
GROUP_TARGETS = {
    "GA": (56, 3, 59),
    "GB": (86, 4, 90),
    "GC": (108, 6, 114),
    "GD": (50, 28, 78),
    "GE": (48, 2, 50),
}
REQUIRED_PHASES = tuple(f"Phase{number}" for number in range(150, 162))
def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SunderkeyError(f"{label} must be a nonempty string")
    return value


def _string_list(value: Any, label: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise SunderkeyError(f"{label} must be a list")
    result = tuple(_string(item, f"{label} item") for item in value)
    if len(result) != len(set(result)):
        raise SunderkeyError(f"{label} contains duplicates")
    return result


def _count_block(raw: Any, label: str, expected: dict[str, int]) -> dict[str, int]:
    value = dict(_mapping(raw, label))
    _exact_fields(value, set(expected), label)
    if value != expected:
        raise SunderkeyError(f"{label} does not match the versioned reference baseline")
    return value


def _profile(raw: Any, label: str, *, expected_command_id: str | None = None) -> dict[str, str]:
    value = dict(_mapping(raw, label))
    _exact_fields(value, {"profile_id", "name"}, label)
    profile_id = _string(value.get("profile_id"), f"{label} profile ID")
    if PROFILE_ID_PATTERN.fullmatch(profile_id) is None:
        raise SunderkeyError(f"{label} profile ID is invalid")
    if expected_command_id is not None and not profile_id.startswith(expected_command_id + "-"):
        raise SunderkeyError(f"{label} does not belong to {expected_command_id}")
    return {"profile_id": profile_id, "name": _string(value.get("name"), f"{label} name")}


def _profiles(
    raw: Any, label: str, *, expected_command_id: str | None = None
) -> tuple[dict[str, str], ...]:
    if not isinstance(raw, list) or not raw:
        raise SunderkeyError(f"{label} must be a nonempty list")
    result = tuple(
        _profile(item, f"{label} item", expected_command_id=expected_command_id) for item in raw
    )
    ids = tuple(item["profile_id"] for item in result)
    if len(ids) != len(set(ids)):
        raise SunderkeyError(f"{label} contains duplicate profile IDs")
    return result


def _command_addition(raw: Any, *, new_command: bool) -> dict[str, Any]:
    label = "new command" if new_command else "existing command addition"
    value = dict(_mapping(raw, label))
    expected_fields = {"command_id", "group_id", "name", "specialists"}
    if new_command:
        expected_fields.add("commander_profile_id")
    _exact_fields(value, expected_fields, label)
    command_id = _string(value.get("command_id"), f"{label} ID")
    group_id = _string(value.get("group_id"), f"{label} group ID")
    if COMMAND_ID_PATTERN.fullmatch(command_id) is None or not command_id.startswith(
        f"AOE-{group_id}-"
    ):
        raise SunderkeyError(f"{label} command or group ID is invalid")
    specialists = _profiles(
        value.get("specialists"),
        f"{command_id} specialists",
        expected_command_id=command_id,
    )
    result: dict[str, Any] = {
        "command_id": command_id,
        "group_id": group_id,
        "name": _string(value.get("name"), f"{command_id} name"),
        "specialists": specialists,
    }
    if new_command:
        commander_id = _string(value.get("commander_profile_id"), "commander profile ID")
        if commander_id != f"{command_id}-CMD":
            raise SunderkeyError(f"{command_id} commander profile ID is invalid")
        result["commander_profile_id"] = commander_id
    return result


def _phase(raw: Any) -> dict[str, Any]:
    value = dict(_mapping(raw, "Army expansion phase"))
    _exact_fields(
        value,
        {
            "phase_id",
            "title",
            "objective",
            "dependency_phase_ids",
            "required_artifacts",
            "completion_gate",
            "operational_effect",
        },
        "Army expansion phase",
    )
    phase_id = _string(value.get("phase_id"), "phase ID")
    if PHASE_ID_PATTERN.fullmatch(phase_id) is None:
        raise SunderkeyError("Army expansion phase ID is invalid")
    if value.get("operational_effect") != "none_without_separate_authority":
        raise SunderkeyError(f"{phase_id} operational effect is invalid")
    return {
        "phase_id": phase_id,
        "title": _string(value.get("title"), f"{phase_id} title"),
        "objective": _string(value.get("objective"), f"{phase_id} objective"),
        "dependency_phase_ids": _string_list(
            value.get("dependency_phase_ids"), f"{phase_id} dependencies"
        ),
        "required_artifacts": _string_list(
            value.get("required_artifacts"), f"{phase_id} required artifacts"
        ),
        "completion_gate": _string(value.get("completion_gate"), f"{phase_id} completion gate"),
        "operational_effect": "none_without_separate_authority",
    }


@dataclass(frozen=True)
class ArmyExpansionRoadmap:
    """Technical Army v2 expansion reference with no operational authority."""

    roadmap_id: str
    roadmap_sha256: str
    baseline_counts: dict[str, int]
    target_counts: dict[str, int]
    delta_counts: dict[str, int]
    new_commands: tuple[dict[str, Any], ...]
    existing_command_additions: tuple[dict[str, Any], ...]
    shared_profile_additions: tuple[dict[str, str], ...]
    phases: tuple[dict[str, Any], ...]
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> ArmyExpansionRoadmap:
        value = dict(_mapping(raw, "Army expansion roadmap"))
        _exact_fields(
            value,
            {
                "schema_version",
                "roadmap_id",
                "roadmap_sha256",
                "program",
                "migration",
                "counts",
                "group_targets",
                "existing_command_additions",
                "new_commands",
                "shared_profile_additions",
                "standards_sources",
                "vector_contract_fields",
                "phases",
                "migration_rules",
                "limitations",
            },
            "Army expansion roadmap",
        )
        if value.get("schema_version") != SCHEMA_VERSION or value.get("program") != "SUNDERKEY":
            raise SunderkeyError("Army expansion roadmap header is invalid")

        migration = dict(_mapping(value.get("migration"), "Army migration"))
        _exact_fields(
            migration,
            {
                "source_catalog",
                "target_catalog",
                "strategy",
                "stable_id_policy",
                "activation_policy",
            },
            "Army migration",
        )
        if migration != {
            "source_catalog": "registry/army-v1.json",
            "target_catalog": "registry/army-v2.json",
            "strategy": "parallel_versioned_migration",
            "stable_id_policy": "preserve_all_v1_profile_ids",
            "activation_policy": "qualified_only_with_separate_routing_authority",
        }:
            raise SunderkeyError("Army migration policy is invalid")

        counts = dict(_mapping(value.get("counts"), "Army expansion counts"))
        _exact_fields(counts, {"baseline", "target", "delta"}, "Army expansion counts")
        baseline = _count_block(counts.get("baseline"), "baseline counts", BASELINE_COUNTS)
        target = _count_block(counts.get("target"), "target counts", TARGET_COUNTS)
        delta = _count_block(counts.get("delta"), "delta counts", DELTA_COUNTS)

        group_targets_raw = value.get("group_targets")
        if not isinstance(group_targets_raw, list) or len(group_targets_raw) != 5:
            raise SunderkeyError("Army group targets are incomplete")
        group_targets: dict[str, tuple[int, int, int]] = {}
        for raw_target in group_targets_raw:
            item = dict(_mapping(raw_target, "Army group target"))
            _exact_fields(
                item,
                {"group_id", "baseline_specialists", "added_specialists", "target_specialists"},
                "Army group target",
            )
            group_id = _string(item.get("group_id"), "group target ID")
            group_targets[group_id] = (
                item.get("baseline_specialists"),
                item.get("added_specialists"),
                item.get("target_specialists"),
            )
        if group_targets != GROUP_TARGETS:
            raise SunderkeyError("Army group targets do not match the reference baseline")

        existing_raw = value.get("existing_command_additions")
        new_raw = value.get("new_commands")
        if not isinstance(existing_raw, list) or not isinstance(new_raw, list):
            raise SunderkeyError("Army command additions must be lists")
        existing = tuple(_command_addition(item, new_command=False) for item in existing_raw)
        new = tuple(_command_addition(item, new_command=True) for item in new_raw)
        if tuple(item["command_id"] for item in new) != ("AOE-GD-D24", "AOE-GD-D25"):
            raise SunderkeyError("Army new commands are incomplete or unordered")
        if len(existing) != 9 or len(new) != 2:
            raise SunderkeyError("Army command addition set is incomplete")

        shared = _profiles(value.get("shared_profile_additions"), "shared profile additions")
        if tuple(item["profile_id"] for item in shared) != (
            "AOE-HQ-33",
            "AOE-HQ-34",
            "AOE-HQ-35",
        ):
            raise SunderkeyError("Army shared profile additions are incomplete or unordered")

        all_specialists = tuple(
            specialist for command in (*existing, *new) for specialist in command["specialists"]
        )
        specialist_ids = tuple(item["profile_id"] for item in all_specialists)
        if len(specialist_ids) != 43 or len(specialist_ids) != len(set(specialist_ids)):
            raise SunderkeyError("Army specialist additions must contain 43 unique profiles")

        sources = value.get("standards_sources")
        if not isinstance(sources, list) or len(sources) < 7:
            raise SunderkeyError("Army standards sources are incomplete")
        source_ids: list[str] = []
        for raw_source in sources:
            source = dict(_mapping(raw_source, "standards source"))
            _exact_fields(source, {"source_id", "version", "url", "use"}, "standards source")
            source_ids.append(_string(source.get("source_id"), "standards source ID"))
            _string(source.get("version"), "standards source version")
            _string(source.get("url"), "standards source URL")
            _string(source.get("use"), "standards source use")
        if len(source_ids) != len(set(source_ids)):
            raise SunderkeyError("Army standards sources contain duplicates")

        vector_fields = _string_list(value.get("vector_contract_fields"), "vector contract fields")
        required_vector_fields = {
            "vector_id",
            "standards_mappings",
            "platforms_and_protocols",
            "primary_specialist_id",
            "supporting_specialist_ids",
            "independent_validator_id",
            "prerequisites_and_observations",
            "allowed_action_tiers",
            "tools_and_credentials",
            "expected_evidence",
            "cleanup_and_restoration",
            "qualification_scenario_id",
            "known_blind_spots",
        }
        if set(vector_fields) != required_vector_fields:
            raise SunderkeyError("Army vector contract fields are incomplete")

        phases_raw = value.get("phases")
        if not isinstance(phases_raw, list):
            raise SunderkeyError("Army expansion phases must be a list")
        phases = tuple(_phase(item) for item in phases_raw)
        if tuple(item["phase_id"] for item in phases) != REQUIRED_PHASES:
            raise SunderkeyError("Army expansion phases are incomplete or unordered")
        known: set[str] = set()
        for phase in phases:
            unknown = set(phase["dependency_phase_ids"]) - known
            if unknown:
                raise SunderkeyError(f"{phase['phase_id']} has unresolved or forward dependencies")
            known.add(phase["phase_id"])

        migration_rules = _string_list(value.get("migration_rules"), "migration rules")
        limitations = _string_list(value.get("limitations"), "roadmap limitations")
        if len(migration_rules) < 5 or len(limitations) < 5:
            raise SunderkeyError("Army migration rules or limitations are incomplete")

        roadmap_id = _string(value.get("roadmap_id"), "Army expansion roadmap ID")
        roadmap_sha256 = _string(value.get("roadmap_sha256"), "Army expansion roadmap hash")
        if (
            ROADMAP_ID_PATTERN.fullmatch(roadmap_id) is None
            or SHA256_PATTERN.fullmatch(roadmap_sha256) is None
        ):
            raise SunderkeyError("Army expansion roadmap identity format is invalid")
        canonical = dict(value)
        canonical.pop("roadmap_id")
        canonical.pop("roadmap_sha256")
        digest = _canonical_sha256({"domain": ROADMAP_DOMAIN, "roadmap": canonical})
        expected_id = f"AER-{digest.removeprefix('sha256:')[:32].upper()}"
        if roadmap_id != expected_id or roadmap_sha256 != digest:
            raise SunderkeyError("Army expansion roadmap identity does not match content")

        return cls(
            roadmap_id=roadmap_id,
            roadmap_sha256=roadmap_sha256,
            baseline_counts=baseline,
            target_counts=target,
            delta_counts=delta,
            new_commands=new,
            existing_command_additions=existing,
            shared_profile_additions=shared,
            phases=phases,
            document_json=_canonical_json(value),
        )

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.document_json)


def build_army_expansion_roadmap(body: dict[str, Any]) -> ArmyExpansionRoadmap:
    """Content-address a technical roadmap body and validate the result."""

    if "roadmap_id" in body or "roadmap_sha256" in body:
        raise SunderkeyError("Army expansion roadmap body must not contain identity fields")
    digest = _canonical_sha256({"domain": ROADMAP_DOMAIN, "roadmap": body})
    document = {
        **body,
        "roadmap_id": f"AER-{digest.removeprefix('sha256:')[:32].upper()}",
        "roadmap_sha256": digest,
    }
    return ArmyExpansionRoadmap.from_dict(document)


def load_army_expansion_roadmap(source: str | Path) -> ArmyExpansionRoadmap:
    resolved = Path(source)
    try:
        raw = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SunderkeyError(f"Could not load Army expansion roadmap: {resolved}") from exc
    return ArmyExpansionRoadmap.from_dict(raw)


__all__ = [
    "ArmyExpansionRoadmap",
    "build_army_expansion_roadmap",
    "load_army_expansion_roadmap",
]

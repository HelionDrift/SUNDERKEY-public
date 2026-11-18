"""Strict attack-vector taxonomy contracts for the Army v2 catalog."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .army_expansion import ArmyExpansionRoadmap
from .errors import RegistryError
from .qualification import _canonical_json, _canonical_sha256, _exact_fields, _mapping
from .registry import ExpertRegistry
from .types import ProfileKind

SCHEMA_VERSION = 1
CATALOG_DOMAIN = "sunderkey.attack-vector-catalog.v2"
CATALOG_ID = "sunderkey-attack-vectors-v2"
CATALOG_VERSION = "2.0.0"
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
VECTOR_ID_PATTERN = re.compile(r"AV-G[A-E]-D[0-9]{2}-S[0-9]{2}-[0-9]{2}")
ALLOWED_VALIDATORS = {
    "AOE-HQ-19",
    "AOE-HQ-33",
    "AOE-HQ-34",
    "AOE-HQ-35",
}
ACTION_TIERS = ("R0", "R1", "R2", "R3", "R4", "R5")


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or not value.isascii():
        raise RegistryError(f"{label} must be nonempty ASCII text")
    return value


def _strings(value: Any, label: str, *, minimum: int = 1) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise RegistryError(f"{label} must be a list")
    result = tuple(_string(item, f"{label} item") for item in value)
    if len(result) < minimum:
        raise RegistryError(f"{label} must contain at least {minimum} items")
    if len(result) != len(set(result)):
        raise RegistryError(f"{label} contains duplicates")
    return result


@dataclass(frozen=True)
class StandardsMapping:
    source_id: str
    source_version: str
    reference_id: str
    relationship: str
    rationale: str

    @classmethod
    def from_dict(cls, raw: Any) -> StandardsMapping:
        value = dict(_mapping(raw, "attack-vector standards mapping"))
        _exact_fields(
            value,
            {"source_id", "source_version", "reference_id", "relationship", "rationale"},
            "attack-vector standards mapping",
        )
        relationship = _string(value.get("relationship"), "mapping relationship")
        if relationship not in {"exact_risk", "related_technique", "contextual_tactic"}:
            raise RegistryError("Attack-vector mapping relationship is invalid")
        return cls(
            source_id=_string(value.get("source_id"), "mapping source ID"),
            source_version=_string(value.get("source_version"), "mapping source version"),
            reference_id=_string(value.get("reference_id"), "mapping reference ID"),
            relationship=relationship,
            rationale=_string(value.get("rationale"), "mapping rationale"),
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "source_id": self.source_id,
            "source_version": self.source_version,
            "reference_id": self.reference_id,
            "relationship": self.relationship,
            "rationale": self.rationale,
        }


@dataclass(frozen=True)
class AttackVector:
    vector_id: str
    name: str
    vector_kind: str
    description: str
    standards_mappings: tuple[StandardsMapping, ...]
    platforms_and_protocols: tuple[str, ...]
    primary_specialist_id: str
    supporting_specialist_ids: tuple[str, ...]
    independent_validator_id: str
    prerequisites_and_observations: tuple[str, ...]
    allowed_action_tiers: tuple[str, ...]
    tools_and_credentials: tuple[str, ...]
    expected_evidence: tuple[str, ...]
    cleanup_and_restoration: tuple[str, ...]
    qualification_scenario_id: str
    known_blind_spots: tuple[str, ...]

    @classmethod
    def from_dict(cls, raw: Any) -> AttackVector:
        value = dict(_mapping(raw, "attack vector"))
        fields = {
            "vector_id",
            "name",
            "vector_kind",
            "description",
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
        _exact_fields(value, fields, "attack vector")
        vector_id = _string(value.get("vector_id"), "attack-vector ID")
        if VECTOR_ID_PATTERN.fullmatch(vector_id) is None:
            raise RegistryError("Attack-vector ID is invalid")
        mappings_raw = value.get("standards_mappings")
        if not isinstance(mappings_raw, list) or not mappings_raw:
            raise RegistryError(f"{vector_id} must contain standards mappings")
        mappings = tuple(StandardsMapping.from_dict(item) for item in mappings_raw)
        mapping_keys = tuple(
            (item.source_id, item.reference_id, item.relationship) for item in mappings
        )
        if len(mapping_keys) != len(set(mapping_keys)):
            raise RegistryError(f"{vector_id} contains duplicate standards mappings")
        tiers = _strings(value.get("allowed_action_tiers"), f"{vector_id} action tiers")
        if tiers not in tuple(ACTION_TIERS[:index] for index in range(1, 7)):
            raise RegistryError(f"{vector_id} action tiers are not a contiguous R0 prefix")
        return cls(
            vector_id=vector_id,
            name=_string(value.get("name"), f"{vector_id} name"),
            vector_kind=_string(value.get("vector_kind"), f"{vector_id} kind"),
            description=_string(value.get("description"), f"{vector_id} description"),
            standards_mappings=mappings,
            platforms_and_protocols=_strings(
                value.get("platforms_and_protocols"), f"{vector_id} platforms"
            ),
            primary_specialist_id=_string(
                value.get("primary_specialist_id"), f"{vector_id} primary specialist"
            ),
            supporting_specialist_ids=_strings(
                value.get("supporting_specialist_ids"),
                f"{vector_id} supporting specialists",
            ),
            independent_validator_id=_string(
                value.get("independent_validator_id"), f"{vector_id} validator"
            ),
            prerequisites_and_observations=_strings(
                value.get("prerequisites_and_observations"),
                f"{vector_id} prerequisites",
            ),
            allowed_action_tiers=tiers,
            tools_and_credentials=_strings(
                value.get("tools_and_credentials"), f"{vector_id} tools"
            ),
            expected_evidence=_strings(value.get("expected_evidence"), f"{vector_id} evidence"),
            cleanup_and_restoration=_strings(
                value.get("cleanup_and_restoration"), f"{vector_id} cleanup"
            ),
            qualification_scenario_id=_string(
                value.get("qualification_scenario_id"), f"{vector_id} scenario ID"
            ),
            known_blind_spots=_strings(value.get("known_blind_spots"), f"{vector_id} blind spots"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "vector_id": self.vector_id,
            "name": self.name,
            "vector_kind": self.vector_kind,
            "description": self.description,
            "standards_mappings": [item.to_dict() for item in self.standards_mappings],
            "platforms_and_protocols": list(self.platforms_and_protocols),
            "primary_specialist_id": self.primary_specialist_id,
            "supporting_specialist_ids": list(self.supporting_specialist_ids),
            "independent_validator_id": self.independent_validator_id,
            "prerequisites_and_observations": list(self.prerequisites_and_observations),
            "allowed_action_tiers": list(self.allowed_action_tiers),
            "tools_and_credentials": list(self.tools_and_credentials),
            "expected_evidence": list(self.expected_evidence),
            "cleanup_and_restoration": list(self.cleanup_and_restoration),
            "qualification_scenario_id": self.qualification_scenario_id,
            "known_blind_spots": list(self.known_blind_spots),
        }


@dataclass(frozen=True)
class AttackVectorCatalog:
    catalog_sha256: str
    standards_sources: tuple[dict[str, str], ...]
    vectors: tuple[AttackVector, ...]
    coverage_summary: dict[str, int]
    limitations: tuple[str, ...]
    document_json: str

    @classmethod
    def from_dict(
        cls,
        raw: Any,
        registry: ExpertRegistry,
        roadmap: ArmyExpansionRoadmap,
    ) -> AttackVectorCatalog:
        value = dict(_mapping(raw, "attack-vector catalog"))
        _exact_fields(
            value,
            {
                "schema_version",
                "catalog_id",
                "catalog_version",
                "catalog_sha256",
                "expert_catalog_id",
                "expert_catalog_version",
                "roadmap_id",
                "roadmap_sha256",
                "catalog_status",
                "operational_effect",
                "standards_sources",
                "vectors",
                "coverage_summary",
                "limitations",
            },
            "attack-vector catalog",
        )
        if (
            value.get("schema_version") != SCHEMA_VERSION
            or value.get("catalog_id") != CATALOG_ID
            or value.get("catalog_version") != CATALOG_VERSION
            or value.get("expert_catalog_id") != registry.catalog_id
            or value.get("expert_catalog_version") != registry.catalog_version
            or value.get("roadmap_id") != roadmap.roadmap_id
            or value.get("roadmap_sha256") != roadmap.roadmap_sha256
            or value.get("catalog_status") != "coverage_anchor_baseline"
            or value.get("operational_effect") != "none"
        ):
            raise RegistryError("Attack-vector catalog binding is invalid")

        source_raw = value.get("standards_sources")
        if not isinstance(source_raw, list):
            raise RegistryError("Attack-vector standards sources must be a list")
        sources: list[dict[str, str]] = []
        for raw_source in source_raw:
            source = dict(_mapping(raw_source, "attack-vector standards source"))
            _exact_fields(
                source,
                {"source_id", "version", "url", "use"},
                "attack-vector standards source",
            )
            sources.append({key: _string(item, f"source {key}") for key, item in source.items()})
        expected_sources = roadmap.to_dict()["standards_sources"]
        if sources != expected_sources:
            raise RegistryError("Attack-vector standards sources do not match D015")
        source_versions = {item["source_id"]: item["version"] for item in sources}

        vectors_raw = value.get("vectors")
        if not isinstance(vectors_raw, list):
            raise RegistryError("Attack vectors must be a list")
        vectors = tuple(AttackVector.from_dict(item) for item in vectors_raw)
        vector_ids = tuple(item.vector_id for item in vectors)
        if len(vector_ids) != len(set(vector_ids)):
            raise RegistryError("Attack-vector IDs are not unique")
        primary_ids = tuple(item.primary_specialist_id for item in vectors)
        specialists = tuple(
            profile for profile in registry.profiles if profile.kind is ProfileKind.SPECIALIST
        )
        specialist_ids = {profile.id for profile in specialists}
        if len(primary_ids) != len(set(primary_ids)) or set(primary_ids) != specialist_ids:
            raise RegistryError("Attack vectors must cover every specialist exactly once")

        profiles = registry.profiles_by_id
        exact_mapping_count = 0
        for vector in vectors:
            primary = profiles.get(vector.primary_specialist_id)
            if primary is None or primary.kind is not ProfileKind.SPECIALIST:
                raise RegistryError(f"{vector.vector_id} primary specialist is invalid")
            expected_id = "AV-" + primary.id.removeprefix("AOE-") + "-01"
            if vector.vector_id != expected_id:
                raise RegistryError(f"{vector.vector_id} does not match its primary specialist")
            if vector.qualification_scenario_id != f"qualification.{primary.id.lower()}":
                raise RegistryError(f"{vector.vector_id} qualification scenario is invalid")
            expected_tier_index = ACTION_TIERS.index(primary.max_autonomous_tier.value)
            if vector.allowed_action_tiers != ACTION_TIERS[: expected_tier_index + 1]:
                raise RegistryError(f"{vector.vector_id} action tiers exceed the profile")
            if primary.id in vector.supporting_specialist_ids:
                raise RegistryError(f"{vector.vector_id} cannot support itself")
            for profile_id in vector.supporting_specialist_ids:
                supporter = profiles.get(profile_id)
                if supporter is None or supporter.kind is not ProfileKind.SPECIALIST:
                    raise RegistryError(f"{vector.vector_id} supporting specialist is invalid")
            validator = profiles.get(vector.independent_validator_id)
            if (
                vector.independent_validator_id not in ALLOWED_VALIDATORS
                or validator is None
                or validator.kind is not ProfileKind.SHARED
            ):
                raise RegistryError(f"{vector.vector_id} independent validator is invalid")
            for mapping in vector.standards_mappings:
                if source_versions.get(mapping.source_id) != mapping.source_version:
                    raise RegistryError(f"{vector.vector_id} standards version is unbound")
                exact_mapping_count += mapping.relationship == "exact_risk"

        coverage = dict(_mapping(value.get("coverage_summary"), "vector coverage summary"))
        expected_coverage = {
            "vector_count": len(vectors),
            "primary_specialist_count": len(set(primary_ids)),
            "specialists_without_primary_vector": len(specialist_ids - set(primary_ids)),
            "vectors_with_supporting_specialists": sum(
                bool(item.supporting_specialist_ids) for item in vectors
            ),
            "vectors_with_external_mapping": sum(bool(item.standards_mappings) for item in vectors),
            "exact_external_mapping_count": exact_mapping_count,
        }
        _exact_fields(coverage, set(expected_coverage), "vector coverage summary")
        if coverage != expected_coverage:
            raise RegistryError("Attack-vector coverage summary is invalid")

        limitations = _strings(value.get("limitations"), "attack-vector limitations", minimum=3)
        catalog_sha256 = _string(value.get("catalog_sha256"), "attack-vector catalog hash")
        if SHA256_PATTERN.fullmatch(catalog_sha256) is None:
            raise RegistryError("Attack-vector catalog hash format is invalid")
        canonical = dict(value)
        canonical.pop("catalog_sha256")
        digest = _canonical_sha256({"domain": CATALOG_DOMAIN, "catalog": canonical})
        if digest != catalog_sha256:
            raise RegistryError("Attack-vector catalog hash does not match content")
        return cls(
            catalog_sha256=catalog_sha256,
            standards_sources=tuple(sources),
            vectors=vectors,
            coverage_summary=coverage,
            limitations=limitations,
            document_json=_canonical_json(value),
        )

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.document_json)


def load_attack_vector_catalog(
    source: str | Path,
    registry: ExpertRegistry,
    roadmap: ArmyExpansionRoadmap,
) -> AttackVectorCatalog:
    path = Path(source)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RegistryError(f"Could not load attack-vector catalog: {path}") from exc
    return AttackVectorCatalog.from_dict(raw, registry, roadmap)


__all__ = ["AttackVector", "AttackVectorCatalog", "StandardsMapping", "load_attack_vector_catalog"]

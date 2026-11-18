"""Strict contracts for the Phase 157 attack-technique reference catalog v3."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import RegistryError

SCHEMA_VERSION = 3
CATALOG_DOMAIN = "sunderkey.attack-technique-catalog.v3"
CATALOG_ID = "sunderkey-attack-techniques-reference-v3"
CATALOG_VERSION = "3.0.0"
CATALOG_STATUS = "infrastructure_independent_reference"
EFFECT_FIELDS = (
    "authority_effect",
    "qualification_effect",
    "routing_effect",
    "execution_effect",
    "deployment_effect",
)
REFERENCE_PROFILES = (
    (
        "AOE-GA-D01-S01",
        "Passive OSINT",
        "AV-GA-D01-S01-01",
        "passive_discovery",
    ),
    (
        "AOE-GB-D06-S09",
        "API object-level authorization",
        "AV-GB-D06-S09-01",
        "api_object_authorization",
    ),
    (
        "AOE-GA-D03-S14",
        "Entitlement graphs and toxic combinations",
        "AV-GA-D03-S14-01",
        "identity_entitlement_paths",
    ),
    (
        "AOE-GC-D14-S01",
        "AWS IAM and Organizations",
        "AV-GC-D14-S01-01",
        "cloud_iam_paths",
    ),
    (
        "AOE-GC-D11-S08",
        "Windows local privilege escalation",
        "AV-GC-D11-S08-01",
        "endpoint_privilege_paths",
    ),
    (
        "AOE-GD-D19-S01",
        "ICS zones and conduits",
        "AV-GD-D19-S01-01",
        "ics_segmentation_and_restoration",
    ),
)

_SHA256 = re.compile(r"sha256:[0-9a-f]{64}")
_TECHNIQUE_ID = re.compile(r"AT3-G[A-E]-D[0-9]{2}-S[0-9]{2}-[0-9]{2}")
_DATE = re.compile(r"20[0-9]{2}-[01][0-9]-[0-3][0-9]")
_UNPINNED = re.compile(r"(?:^|[ _-])(latest|current|rolling|stable|unversioned)(?:$|[ _-])", re.I)
_GENERIC_MECHANICS = (
    "provider-neutral specialist tool adapter selected by policy",
    "exact authorized target and scope binding are available",
    "a reproducible baseline and relevant observable signals are available",
    "specialist coverage anchor",
)
_SOURCE_RELATIONSHIPS = {
    "mitre-attack-enterprise": {"related_technique"},
    "owasp-api-security": {"exact_risk"},
    "iec-62443-3-3": {"control_alignment"},
}
_EXPECTED_SOURCES = {
    "iec-62443-3-3": {
        "title": "IEC 62443-3-3:2013 Industrial communication networks security",
        "publisher": "International Electrotechnical Commission",
        "source_version": "IEC 62443-3-3:2013",
        "release_date": "2013-08-07",
        "url": "https://webstore.iec.ch/en/publication/7033",
        "reference_ids": ("SR 5.1", "SR 5.2", "SR 7.4"),
    },
    "mitre-attack-enterprise": {
        "title": "MITRE ATT&CK Enterprise",
        "publisher": "MITRE",
        "source_version": "19.2",
        "release_date": "2026-08-05",
        "url": "https://github.com/mitre-attack/attack-stix-data/releases/tag/v19.2",
        "reference_ids": (
            "T1053.005",
            "T1069.002",
            "T1069.003",
            "T1087.004",
            "T1098",
            "T1098.003",
            "T1543.003",
            "T1547.001",
            "T1593.003",
            "T1596.001",
            "T1596.003",
        ),
    },
    "owasp-api-security": {
        "title": "OWASP API Security Top 10",
        "publisher": "OWASP Foundation",
        "source_version": "2023",
        "release_date": "2023-07-03",
        "url": "https://owasp.org/API-Security/editions/2023/en/0x11-t10/",
        "reference_ids": ("API1:2023",),
    },
}


def canonical_json(value: Any) -> str:
    """Return the single canonical JSON representation used for digests."""

    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise RegistryError("Could not serialize canonical attack-technique data") from exc


def canonical_sha256(value: Any) -> str:
    """Hash canonical JSON using the catalog's explicit sha256 prefix."""

    return "sha256:" + hashlib.sha256(canonical_json(value).encode("ascii")).hexdigest()


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RegistryError(f"{label} must be an object")
    return value


def _exact(value: Mapping[str, Any], fields: set[str], label: str) -> None:
    actual = set(value)
    if actual != fields:
        missing = sorted(fields - actual)
        extra = sorted(actual - fields)
        raise RegistryError(f"{label} fields are invalid: missing={missing}, extra={extra}")


def _text(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or not value.isascii()
        or "\u2013" in value
        or "\u2014" in value
    ):
        raise RegistryError(f"{label} must be nonempty ASCII text")
    return value


def _strings(value: Any, label: str, minimum: int = 1) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise RegistryError(f"{label} must be a list")
    result = tuple(_text(item, f"{label} item") for item in value)
    if len(result) < minimum:
        raise RegistryError(f"{label} must contain at least {minimum} items")
    if len(set(result)) != len(result):
        raise RegistryError(f"{label} contains duplicates")
    return result


def _none_effects(value: Mapping[str, Any], label: str) -> None:
    if any(value.get(field) != "none" for field in EFFECT_FIELDS):
        raise RegistryError(f"{label} effect fields must all be none")


@dataclass(frozen=True)
class StandardsSource:
    """A release-pinned primary standards source with allowed references."""

    source_id: str
    title: str
    publisher: str
    source_version: str
    release_date: str
    url: str
    reference_ids: tuple[str, ...]

    @classmethod
    def from_dict(cls, raw: Any) -> StandardsSource:
        value = _object(raw, "standards source")
        _exact(
            value,
            {
                "source_id",
                "title",
                "publisher",
                "source_version",
                "release_date",
                "url",
                "reference_ids",
            },
            "standards source",
        )
        source_id = _text(value.get("source_id"), "source ID")
        version = _text(value.get("source_version"), f"{source_id} version")
        if _UNPINNED.search(version):
            raise RegistryError(f"{source_id} source version is not pinned")
        release_date = _text(value.get("release_date"), f"{source_id} release date")
        if _DATE.fullmatch(release_date) is None:
            raise RegistryError(f"{source_id} release date is not pinned")
        references = _strings(value.get("reference_ids"), f"{source_id} references")
        return cls(
            source_id=source_id,
            title=_text(value.get("title"), f"{source_id} title"),
            publisher=_text(value.get("publisher"), f"{source_id} publisher"),
            source_version=version,
            release_date=release_date,
            url=_text(value.get("url"), f"{source_id} URL"),
            reference_ids=references,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "title": self.title,
            "publisher": self.publisher,
            "source_version": self.source_version,
            "release_date": self.release_date,
            "url": self.url,
            "reference_ids": list(self.reference_ids),
        }


@dataclass(frozen=True)
class StandardsMapping:
    """A technique mapping bound to one exact source release."""

    source_id: str
    source_version: str
    source_release_date: str
    reference_id: str
    relationship: str
    rationale: str

    @classmethod
    def from_dict(cls, raw: Any) -> StandardsMapping:
        value = _object(raw, "standards mapping")
        _exact(
            value,
            {
                "source_id",
                "source_version",
                "source_release_date",
                "reference_id",
                "relationship",
                "rationale",
            },
            "standards mapping",
        )
        return cls(
            source_id=_text(value.get("source_id"), "mapping source ID"),
            source_version=_text(value.get("source_version"), "mapping source version"),
            source_release_date=_text(
                value.get("source_release_date"), "mapping source release date"
            ),
            reference_id=_text(value.get("reference_id"), "mapping reference ID"),
            relationship=_text(value.get("relationship"), "mapping relationship"),
            rationale=_text(value.get("rationale"), "mapping rationale"),
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "source_id": self.source_id,
            "source_version": self.source_version,
            "source_release_date": self.source_release_date,
            "reference_id": self.reference_id,
            "relationship": self.relationship,
            "rationale": self.rationale,
        }


@dataclass(frozen=True)
class AttackTechnique:
    """One non-operational, infrastructure-independent analysis path."""

    technique_id: str
    profile_id: str
    vector_id: str
    name: str
    family: str
    record_kind: str
    mechanic: str
    description: str
    prerequisites: tuple[str, ...]
    observables: tuple[str, ...]
    safe_proof: tuple[str, ...]
    negative_controls: tuple[str, ...]
    cleanup_and_restoration: tuple[str, ...]
    blind_spots: tuple[str, ...]
    standards_mappings: tuple[StandardsMapping, ...]
    authority_effect: str
    qualification_effect: str
    routing_effect: str
    execution_effect: str
    deployment_effect: str
    technique_sha256: str

    @classmethod
    def from_dict(cls, raw: Any) -> AttackTechnique:
        value = _object(raw, "attack technique")
        fields = {
            "technique_id",
            "profile_id",
            "vector_id",
            "name",
            "family",
            "record_kind",
            "mechanic",
            "description",
            "prerequisites",
            "observables",
            "safe_proof",
            "negative_controls",
            "cleanup_and_restoration",
            "blind_spots",
            "standards_mappings",
            *EFFECT_FIELDS,
            "technique_sha256",
        }
        _exact(value, fields, "attack technique")
        technique_id = _text(value.get("technique_id"), "technique ID")
        if _TECHNIQUE_ID.fullmatch(technique_id) is None:
            raise RegistryError("Attack-technique ID is invalid")
        if value.get("record_kind") not in {"technique", "path"}:
            raise RegistryError(f"{technique_id} record kind is invalid")
        _none_effects(value, technique_id)
        mappings_raw = value.get("standards_mappings")
        if not isinstance(mappings_raw, list) or not mappings_raw:
            raise RegistryError(f"{technique_id} must contain standards mappings")
        mappings = tuple(StandardsMapping.from_dict(item) for item in mappings_raw)
        mapping_keys = tuple(
            (
                item.source_id,
                item.source_version,
                item.source_release_date,
                item.reference_id,
                item.relationship,
            )
            for item in mappings
        )
        if len(mapping_keys) != len(set(mapping_keys)):
            raise RegistryError(f"{technique_id} contains duplicate standards mappings")
        digest = _text(value.get("technique_sha256"), f"{technique_id} hash")
        if _SHA256.fullmatch(digest) is None:
            raise RegistryError(f"{technique_id} hash format is invalid")
        canonical = dict(value)
        canonical.pop("technique_sha256")
        expected = canonical_sha256(
            {"domain": f"{CATALOG_DOMAIN}.technique", "technique": canonical}
        )
        if digest != expected:
            raise RegistryError(f"{technique_id} hash does not match content")
        return cls(
            technique_id=technique_id,
            profile_id=_text(value.get("profile_id"), f"{technique_id} profile ID"),
            vector_id=_text(value.get("vector_id"), f"{technique_id} vector ID"),
            name=_text(value.get("name"), f"{technique_id} name"),
            family=_text(value.get("family"), f"{technique_id} family"),
            record_kind=value["record_kind"],
            mechanic=_text(value.get("mechanic"), f"{technique_id} mechanic"),
            description=_text(value.get("description"), f"{technique_id} description"),
            prerequisites=_strings(value.get("prerequisites"), f"{technique_id} prerequisites", 2),
            observables=_strings(value.get("observables"), f"{technique_id} observables", 2),
            safe_proof=_strings(value.get("safe_proof"), f"{technique_id} safe proof", 2),
            negative_controls=_strings(
                value.get("negative_controls"), f"{technique_id} negative controls", 2
            ),
            cleanup_and_restoration=_strings(
                value.get("cleanup_and_restoration"),
                f"{technique_id} cleanup and restoration",
                2,
            ),
            blind_spots=_strings(value.get("blind_spots"), f"{technique_id} blind spots", 2),
            standards_mappings=mappings,
            authority_effect=value["authority_effect"],
            qualification_effect=value["qualification_effect"],
            routing_effect=value["routing_effect"],
            execution_effect=value["execution_effect"],
            deployment_effect=value["deployment_effect"],
            technique_sha256=digest,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "profile_id": self.profile_id,
            "vector_id": self.vector_id,
            "name": self.name,
            "family": self.family,
            "record_kind": self.record_kind,
            "mechanic": self.mechanic,
            "description": self.description,
            "prerequisites": list(self.prerequisites),
            "observables": list(self.observables),
            "safe_proof": list(self.safe_proof),
            "negative_controls": list(self.negative_controls),
            "cleanup_and_restoration": list(self.cleanup_and_restoration),
            "blind_spots": list(self.blind_spots),
            "standards_mappings": [item.to_dict() for item in self.standards_mappings],
            **{field: getattr(self, field) for field in EFFECT_FIELDS},
            "technique_sha256": self.technique_sha256,
        }


@dataclass(frozen=True)
class AttackTechniqueCatalog:
    """Validated immutable view of the v3 reference catalog."""

    catalog_sha256: str
    standards_sources: tuple[StandardsSource, ...]
    techniques: tuple[AttackTechnique, ...]
    coverage_summary: dict[str, int]
    limitations: tuple[str, ...]
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> AttackTechniqueCatalog:
        value = _object(raw, "attack-technique catalog")
        fields = {
            "schema_version",
            "catalog_id",
            "catalog_version",
            "catalog_sha256",
            "catalog_status",
            "reference_profiles",
            "standards_sources",
            "techniques",
            "coverage_summary",
            *EFFECT_FIELDS,
            "limitations",
        }
        _exact(value, fields, "attack-technique catalog")
        if (
            value.get("schema_version") != SCHEMA_VERSION
            or value.get("catalog_id") != CATALOG_ID
            or value.get("catalog_version") != CATALOG_VERSION
            or value.get("catalog_status") != CATALOG_STATUS
        ):
            raise RegistryError("Attack-technique catalog binding is invalid")
        _none_effects(value, "attack-technique catalog")

        expected_profiles = [
            {
                "profile_id": profile_id,
                "profile_name": name,
                "vector_id": vector_id,
                "family": family,
            }
            for profile_id, name, vector_id, family in REFERENCE_PROFILES
        ]
        if value.get("reference_profiles") != expected_profiles:
            raise RegistryError("Attack-technique reference profiles are invalid")

        sources_raw = value.get("standards_sources")
        if not isinstance(sources_raw, list) or not sources_raw:
            raise RegistryError("Attack-technique standards sources must be a list")
        sources = tuple(StandardsSource.from_dict(item) for item in sources_raw)
        source_ids = tuple(item.source_id for item in sources)
        if len(source_ids) != len(set(source_ids)):
            raise RegistryError("Attack-technique standards source IDs are not unique")
        if source_ids != tuple(sorted(source_ids)):
            raise RegistryError("Attack-technique standards sources are not deterministic")
        source_index = {item.source_id: item for item in sources}
        if set(source_index) != set(_SOURCE_RELATIONSHIPS):
            raise RegistryError("Attack-technique source pins are incomplete")
        for source_id, source in source_index.items():
            expected = _EXPECTED_SOURCES[source_id]
            actual = source.to_dict()
            actual.pop("source_id")
            actual["reference_ids"] = tuple(actual["reference_ids"])
            if actual != expected:
                raise RegistryError(f"{source_id} source pin is invalid")

        techniques_raw = value.get("techniques")
        if not isinstance(techniques_raw, list):
            raise RegistryError("Attack techniques must be a list")
        techniques = tuple(AttackTechnique.from_dict(item) for item in techniques_raw)
        technique_ids = tuple(item.technique_id for item in techniques)
        if len(technique_ids) != len(set(technique_ids)):
            raise RegistryError("Attack-technique IDs are not unique")
        if technique_ids != tuple(sorted(technique_ids)):
            raise RegistryError("Attack techniques are not in deterministic ID order")

        profiles = {item[0]: item for item in REFERENCE_PROFILES}
        per_profile = {item[0]: 0 for item in REFERENCE_PROFILES}
        mechanics: set[str] = set()
        detail_signatures: set[str] = set()
        used_sources: set[str] = set()
        for technique in techniques:
            profile = profiles.get(technique.profile_id)
            if profile is None:
                raise RegistryError(
                    f"{technique.technique_id} profile is not in the reference slice"
                )
            _, _, vector_id, family = profile
            if technique.vector_id != vector_id or technique.family != family:
                raise RegistryError(f"{technique.technique_id} profile binding is invalid")
            expected_prefix = "AT3-" + technique.profile_id.removeprefix("AOE-") + "-"
            if not technique.technique_id.startswith(expected_prefix):
                raise RegistryError(f"{technique.technique_id} does not match its profile")
            per_profile[technique.profile_id] += 1

            normalized_mechanic = " ".join(technique.mechanic.lower().split())
            if normalized_mechanic in mechanics:
                raise RegistryError("Attack techniques contain generic repeated mechanics")
            if any(phrase in normalized_mechanic for phrase in _GENERIC_MECHANICS):
                raise RegistryError(f"{technique.technique_id} uses a generic mechanic")
            mechanics.add(normalized_mechanic)
            details = canonical_sha256(
                {
                    "prerequisites": technique.prerequisites,
                    "observables": technique.observables,
                    "safe_proof": technique.safe_proof,
                    "negative_controls": technique.negative_controls,
                    "cleanup_and_restoration": technique.cleanup_and_restoration,
                    "blind_spots": technique.blind_spots,
                }
            )
            if details in detail_signatures:
                raise RegistryError("Attack techniques contain generic repeated mechanics")
            detail_signatures.add(details)

            for mapping in technique.standards_mappings:
                source = source_index.get(mapping.source_id)
                if source is None:
                    raise RegistryError(f"{technique.technique_id} mapping source is unknown")
                if (
                    mapping.source_version != source.source_version
                    or mapping.source_release_date != source.release_date
                ):
                    raise RegistryError(f"{technique.technique_id} mapping source pin is invalid")
                if mapping.reference_id not in source.reference_ids:
                    raise RegistryError(f"{technique.technique_id} mapping reference is invalid")
                if mapping.relationship not in _SOURCE_RELATIONSHIPS[mapping.source_id]:
                    raise RegistryError(f"{technique.technique_id} mapping relationship is invalid")
                used_sources.add(mapping.source_id)

        if any(count != 3 for count in per_profile.values()):
            raise RegistryError("Each reference profile requires three concrete techniques")
        expected_ordinals = {
            profile_id: tuple(
                f"AT3-{profile_id.removeprefix('AOE-')}-{index:02d}"
                for index in range(1, count + 1)
            )
            for profile_id, count in per_profile.items()
        }
        for profile_id, expected in expected_ordinals.items():
            actual = tuple(
                item.technique_id for item in techniques if item.profile_id == profile_id
            )
            if actual != expected:
                raise RegistryError(f"{profile_id} technique ordinals are not contiguous")
        if used_sources != set(source_index):
            raise RegistryError("Attack-technique source pins are not all mapped")

        coverage = _object(value.get("coverage_summary"), "attack-technique coverage summary")
        expected_coverage = {
            "reference_profile_count": len(REFERENCE_PROFILES),
            "technique_count": len(techniques),
            "profiles_with_multiple_techniques": sum(count >= 2 for count in per_profile.values()),
            "standards_source_count": len(sources),
            "mapped_technique_count": sum(bool(item.standards_mappings) for item in techniques),
            "unique_mechanic_count": len(mechanics),
            "non_operational_technique_count": sum(
                all(getattr(item, field) == "none" for field in EFFECT_FIELDS)
                for item in techniques
            ),
        }
        _exact(coverage, set(expected_coverage), "attack-technique coverage summary")
        if coverage != expected_coverage:
            raise RegistryError("Attack-technique coverage summary is invalid")

        limitations = _strings(value.get("limitations"), "attack-technique limitations", 3)
        catalog_sha256 = _text(value.get("catalog_sha256"), "attack-technique catalog hash")
        if _SHA256.fullmatch(catalog_sha256) is None:
            raise RegistryError("Attack-technique catalog hash format is invalid")
        canonical = dict(value)
        canonical.pop("catalog_sha256")
        digest = canonical_sha256({"domain": CATALOG_DOMAIN, "catalog": canonical})
        if digest != catalog_sha256:
            raise RegistryError("Attack-technique catalog hash does not match content")
        return cls(
            catalog_sha256=catalog_sha256,
            standards_sources=sources,
            techniques=techniques,
            coverage_summary=coverage,
            limitations=limitations,
            document_json=canonical_json(value),
        )

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.document_json)


def load_attack_technique_catalog_v3(source: str | Path) -> AttackTechniqueCatalog:
    """Load and strictly validate a v3 attack-technique catalog."""

    path = Path(source)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RegistryError(f"Could not load attack-technique catalog: {path}") from exc
    return AttackTechniqueCatalog.from_dict(raw)


load_attack_technique_catalog = load_attack_technique_catalog_v3
AttackTechniqueV3 = AttackTechnique
AttackTechniqueCatalogV3 = AttackTechniqueCatalog

__all__ = [
    "AttackTechnique",
    "AttackTechniqueCatalog",
    "AttackTechniqueCatalogV3",
    "AttackTechniqueV3",
    "CATALOG_DOMAIN",
    "CATALOG_ID",
    "CATALOG_STATUS",
    "CATALOG_VERSION",
    "EFFECT_FIELDS",
    "REFERENCE_PROFILES",
    "SCHEMA_VERSION",
    "StandardsMapping",
    "StandardsSource",
    "canonical_json",
    "canonical_sha256",
    "load_attack_technique_catalog",
    "load_attack_technique_catalog_v3",
]

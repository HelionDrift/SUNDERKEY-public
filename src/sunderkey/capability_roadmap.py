"""Validated program roadmap and evidence-gate projections."""

from __future__ import annotations

import json
import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import SunderkeyError
from .qualification import _canonical_json, _canonical_sha256, _exact_fields, _mapping

SCHEMA_VERSION = 1
ROADMAP_DOMAIN = "sunderkey.capability-roadmap.v1"
ROADMAP_ID_PATTERN = re.compile(r"CRD-[0-9A-F]{32}")
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}")
PACKAGE_ID_PATTERN = re.compile(r"(?:R|X|A|E|C|P|S|D)[0-9]+\.[0-9]+")
GATE_ID_PATTERN = re.compile(r"G[0-9]+")
RELEASE_STATES = (
    "planned",
    "implemented",
    "qualified",
    "deployed",
    "production_authorized",
    "generally_available",
)


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


@dataclass(frozen=True)
class RoadmapPackage:
    package_id: str
    title: str
    owner_role: str
    dependency_package_ids: tuple[str, ...]
    completion_result: str

    @classmethod
    def from_dict(cls, raw: Any) -> RoadmapPackage:
        value = _mapping(raw, "capability roadmap package")
        _exact_fields(
            value,
            {
                "package_id",
                "title",
                "owner_role",
                "dependency_package_ids",
                "completion_result",
            },
            "capability roadmap package",
        )
        package_id = _string(value.get("package_id"), "package ID")
        if PACKAGE_ID_PATTERN.fullmatch(package_id) is None:
            raise SunderkeyError("Capability roadmap package ID is invalid")
        dependencies = _string_list(
            value.get("dependency_package_ids"),
            f"{package_id} dependencies",
        )
        if package_id in dependencies:
            raise SunderkeyError(f"{package_id} cannot depend on itself")
        return cls(
            package_id=package_id,
            title=_string(value.get("title"), f"{package_id} title"),
            owner_role=_string(value.get("owner_role"), f"{package_id} owner role"),
            dependency_package_ids=dependencies,
            completion_result=_string(
                value.get("completion_result"),
                f"{package_id} completion result",
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "package_id": self.package_id,
            "title": self.title,
            "owner_role": self.owner_role,
            "dependency_package_ids": list(self.dependency_package_ids),
            "completion_result": self.completion_result,
        }


@dataclass(frozen=True)
class EvidenceGate:
    gate_id: str
    title: str
    evidence_requirements: tuple[str, ...]

    @classmethod
    def from_dict(cls, raw: Any) -> EvidenceGate:
        value = _mapping(raw, "capability roadmap gate")
        _exact_fields(
            value,
            {"gate_id", "title", "evidence_requirements"},
            "capability roadmap gate",
        )
        gate_id = _string(value.get("gate_id"), "gate ID")
        if GATE_ID_PATTERN.fullmatch(gate_id) is None:
            raise SunderkeyError("Capability roadmap gate ID is invalid")
        evidence = _string_list(
            value.get("evidence_requirements"),
            f"{gate_id} evidence requirements",
        )
        if not evidence:
            raise SunderkeyError(f"{gate_id} must require evidence")
        return cls(
            gate_id=gate_id,
            title=_string(value.get("title"), f"{gate_id} title"),
            evidence_requirements=evidence,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "gate_id": self.gate_id,
            "title": self.title,
            "evidence_requirements": list(self.evidence_requirements),
        }


@dataclass(frozen=True)
class RoadmapIncrement:
    increment_id: str
    title: str
    objective: str
    packages: tuple[RoadmapPackage, ...]
    gate: EvidenceGate

    @classmethod
    def from_dict(cls, raw: Any) -> RoadmapIncrement:
        value = _mapping(raw, "capability roadmap increment")
        _exact_fields(
            value,
            {"increment_id", "title", "objective", "packages", "gate"},
            "capability roadmap increment",
        )
        increment_id = _string(value.get("increment_id"), "increment ID")
        if not re.fullmatch(r"I[0-8]", increment_id):
            raise SunderkeyError("Capability roadmap increment ID is invalid")
        packages_raw = value.get("packages")
        if not isinstance(packages_raw, list) or not packages_raw:
            raise SunderkeyError(f"{increment_id} must contain packages")
        return cls(
            increment_id=increment_id,
            title=_string(value.get("title"), f"{increment_id} title"),
            objective=_string(value.get("objective"), f"{increment_id} objective"),
            packages=tuple(RoadmapPackage.from_dict(item) for item in packages_raw),
            gate=EvidenceGate.from_dict(value.get("gate")),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "increment_id": self.increment_id,
            "title": self.title,
            "objective": self.objective,
            "packages": [package.to_dict() for package in self.packages],
            "gate": self.gate.to_dict(),
        }


@dataclass(frozen=True)
class CapabilityRoadmap:
    roadmap_id: str
    roadmap_sha256: str
    program: str
    status: str
    roadmap_effect: str
    baseline: dict[str, Any]
    release_states: tuple[str, ...]
    scorecard_measures: tuple[str, ...]
    increments: tuple[RoadmapIncrement, ...]
    limitations: tuple[str, ...]
    document_json: str

    @classmethod
    def from_dict(cls, raw: Any) -> CapabilityRoadmap:
        value = _mapping(raw, "capability roadmap")
        _exact_fields(
            value,
            {
                "schema_version",
                "roadmap_id",
                "roadmap_sha256",
                "program",
                "status",
                "roadmap_effect",
                "baseline",
                "release_states",
                "scorecard_measures",
                "increments",
                "limitations",
            },
            "capability roadmap",
        )
        if value.get("schema_version") != SCHEMA_VERSION:
            raise SunderkeyError("Capability roadmap schema is invalid")
        roadmap_id = _string(value.get("roadmap_id"), "roadmap ID")
        roadmap_sha256 = _string(value.get("roadmap_sha256"), "roadmap hash")
        if ROADMAP_ID_PATTERN.fullmatch(roadmap_id) is None:
            raise SunderkeyError("Capability roadmap identity is invalid")
        if SHA256_PATTERN.fullmatch(roadmap_sha256) is None:
            raise SunderkeyError("Capability roadmap hash format is invalid")
        if value.get("program") != "SUNDERKEY":
            raise SunderkeyError("Capability roadmap program is invalid")
        if value.get("status") != "approved_planning_baseline":
            raise SunderkeyError("Capability roadmap status is invalid")
        if value.get("roadmap_effect") != "planning_only":
            raise SunderkeyError("Capability roadmap effect is invalid")

        baseline = dict(_mapping(value.get("baseline"), "capability roadmap baseline"))
        _exact_fields(
            baseline,
            {"source_commit", "software_version", "planning_version"},
            "capability roadmap baseline",
        )
        source_commit = _string(baseline.get("source_commit"), "source commit")
        if re.fullmatch(r"[0-9a-f]{40}", source_commit) is None:
            raise SunderkeyError("Capability roadmap source commit is invalid")
        _string(baseline.get("software_version"), "software version")
        _string(baseline.get("planning_version"), "planning version")

        release_states = _string_list(value.get("release_states"), "release states")
        if release_states != RELEASE_STATES:
            raise SunderkeyError("Capability roadmap release states are invalid")
        measures = _string_list(
            value.get("scorecard_measures"),
            "scorecard measures",
        )
        if not measures:
            raise SunderkeyError("Capability roadmap scorecard is empty")
        increments_raw = value.get("increments")
        if not isinstance(increments_raw, list):
            raise SunderkeyError("Capability roadmap increments must be a list")
        increments = tuple(RoadmapIncrement.from_dict(item) for item in increments_raw)
        if tuple(item.increment_id for item in increments) != tuple(
            f"I{index}" for index in range(9)
        ):
            raise SunderkeyError("Capability roadmap increments are incomplete or unordered")

        packages = tuple(package for item in increments for package in item.packages)
        package_ids = tuple(package.package_id for package in packages)
        if len(package_ids) != len(set(package_ids)):
            raise SunderkeyError("Capability roadmap package IDs are not unique")
        gate_ids = tuple(item.gate.gate_id for item in increments)
        if gate_ids != tuple(f"G{index}" for index in range(9)):
            raise SunderkeyError("Capability roadmap gates are incomplete or unordered")
        known: set[str] = set()
        for package in packages:
            unknown = set(package.dependency_package_ids) - known
            if unknown:
                raise SunderkeyError(
                    f"{package.package_id} has unresolved or forward dependencies"
                )
            known.add(package.package_id)

        limitations = _string_list(value.get("limitations"), "roadmap limitations")
        if not limitations:
            raise SunderkeyError("Capability roadmap limitations are empty")
        canonical = dict(value)
        canonical.pop("roadmap_id")
        canonical.pop("roadmap_sha256")
        digest = _canonical_sha256({"domain": ROADMAP_DOMAIN, "roadmap": canonical})
        if roadmap_id != f"CRD-{digest.removeprefix('sha256:')[:32].upper()}":
            raise SunderkeyError("Capability roadmap identity does not match content")
        if roadmap_sha256 != digest:
            raise SunderkeyError("Capability roadmap hash does not match content")
        return cls(
            roadmap_id=roadmap_id,
            roadmap_sha256=roadmap_sha256,
            program="SUNDERKEY",
            status="approved_planning_baseline",
            roadmap_effect="planning_only",
            baseline=baseline,
            release_states=release_states,
            scorecard_measures=measures,
            increments=increments,
            limitations=limitations,
            document_json=_canonical_json(value),
        )

    def to_dict(self) -> dict[str, Any]:
        return json.loads(self.document_json)

    @property
    def packages(self) -> tuple[RoadmapPackage, ...]:
        return tuple(package for item in self.increments for package in item.packages)


def assess_capability_roadmap(
    roadmap: CapabilityRoadmap,
    completed_package_ids: Iterable[str] = (),
) -> dict[str, Any]:
    """Project ready, blocked, completed, and gate states without mutation."""

    completed = tuple(completed_package_ids)
    if len(completed) != len(set(completed)):
        raise SunderkeyError("Completed capability roadmap packages contain duplicates")
    known = {package.package_id for package in roadmap.packages}
    unknown = set(completed) - known
    if unknown:
        raise SunderkeyError("Completed capability roadmap package is unknown")
    completed_set = set(completed)
    package_states: list[dict[str, Any]] = []
    counts: Counter[str] = Counter()
    for package in roadmap.packages:
        if package.package_id in completed_set:
            state = "completed"
            blockers: tuple[str, ...] = ()
        else:
            blockers = tuple(
                item
                for item in package.dependency_package_ids
                if item not in completed_set
            )
            state = "blocked_by_dependencies" if blockers else "ready"
        counts[state] += 1
        package_states.append(
            {
                "package_id": package.package_id,
                "state": state,
                "blocking_package_ids": list(blockers),
            }
        )

    gates: list[dict[str, Any]] = []
    for increment in roadmap.increments:
        package_ids = tuple(package.package_id for package in increment.packages)
        missing = tuple(item for item in package_ids if item not in completed_set)
        gates.append(
            {
                "gate_id": increment.gate.gate_id,
                "state": "ready_for_evidence_review" if not missing else "waiting_on_packages",
                "incomplete_package_ids": list(missing),
            }
        )
    return {
        "roadmap_id": roadmap.roadmap_id,
        "roadmap_sha256": roadmap.roadmap_sha256,
        "status": "valid",
        "roadmap_effect": "none",
        "package_counts": {
            "total": len(roadmap.packages),
            "completed": counts["completed"],
            "ready": counts["ready"],
            "blocked_by_dependencies": counts["blocked_by_dependencies"],
        },
        "package_states": package_states,
        "gates": gates,
    }


def load_capability_roadmap(source: str | Path) -> CapabilityRoadmap:
    resolved = Path(source)
    try:
        raw = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SunderkeyError(f"Could not load capability roadmap: {resolved}") from exc
    return CapabilityRoadmap.from_dict(raw)


__all__ = [
    "CapabilityRoadmap",
    "EvidenceGate",
    "RoadmapIncrement",
    "RoadmapPackage",
    "assess_capability_roadmap",
    "load_capability_roadmap",
]

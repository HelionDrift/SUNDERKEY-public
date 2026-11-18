#!/usr/bin/env python3
# ruff: noqa: E501
"""Build the deterministic Army v2 attack-vector coverage baseline."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from sunderkey.army_expansion import load_army_expansion_roadmap
from sunderkey.attack_vectors import (
    CATALOG_DOMAIN,
    AttackVectorCatalog,
)
from sunderkey.qualification import _canonical_sha256
from sunderkey.registry import load_registry

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REGISTRY = ROOT / "registry" / "army-v2.json"
DEFAULT_ROADMAP = ROOT / "registry" / "army-expansion-roadmap-v1.json"
DEFAULT_OUTPUT = ROOT / "registry" / "attack-vectors-v2.json"

COMMAND_TACTICS = {
    "AOE-GA-D01": "enterprise:TA0043",
    "AOE-GA-D02": "enterprise:TA0001",
    "AOE-GA-D03": "enterprise:TA0006",
    "AOE-GA-D04": "enterprise:TA0042",
    "AOE-GB-D05": "enterprise:TA0001",
    "AOE-GB-D06": "enterprise:TA0001",
    "AOE-GB-D07": "enterprise:TA0009",
    "AOE-GB-D08": "enterprise:TA0002",
    "AOE-GB-D09": "enterprise:TA0040",
    "AOE-GB-D10": "enterprise:TA0040",
    "AOE-GC-D11": "enterprise:TA0008",
    "AOE-GC-D12": "enterprise:TA0002",
    "AOE-GC-D13": "enterprise:TA0011",
    "AOE-GC-D14": "enterprise:TA0003",
    "AOE-GC-D15": "enterprise:TA0003",
    "AOE-GC-D16": "enterprise:TA0008",
    "AOE-GC-D17": "enterprise:TA0042",
    "AOE-GD-D18": "enterprise:TA0005",
    "AOE-GD-D19": "ics:TA0105",
    "AOE-GE-D21": "enterprise:TA0002",
    "AOE-GE-D22": "enterprise:TA0006",
    "AOE-GE-D23": "enterprise:TA0005",
    "AOE-GD-D24": "enterprise:TA0005",
    "AOE-GD-D25": "enterprise:TA0040",
}

API_RISKS = {
    "AOE-GB-D06-S09": ("API1:2023", "exact_risk"),
    "AOE-GB-D06-S10": ("API5:2023", "exact_risk"),
    "AOE-GB-D06-S11": ("API3:2023", "exact_risk"),
    "AOE-GB-D06-S13": ("API4:2023", "exact_risk"),
    "AOE-GB-D06-S14": ("API9:2023", "exact_risk"),
    "AOE-GB-D06-S15": ("API10:2023", "exact_risk"),
    "AOE-GB-D06-S16": ("API10:2023", "related_technique"),
}

AGENTIC_RISKS = {
    "AOE-GD-D20-S07": ("ASI05", "related_technique"),
    "AOE-GD-D20-S08": ("ASI04", "exact_risk"),
    "AOE-GD-D20-S14": ("ASI02", "exact_risk"),
    "AOE-GD-D20-S15": ("ASI03", "exact_risk"),
    "AOE-GD-D20-S16": ("ASI06", "related_technique"),
    "AOE-GD-D20-S19": ("ASI01", "exact_risk"),
    "AOE-GD-D20-S20": ("ASI08", "related_technique"),
}

NIST_AI_CATEGORIES = {
    "AOE-GD-D20-S02": "attack-category:poisoning",
    "AOE-GD-D20-S03": "attack-category:poisoning",
    "AOE-GD-D20-S04": "attack-category:evasion",
    "AOE-GD-D20-S05": "attack-category:privacy",
    "AOE-GD-D20-S06": "attack-category:privacy",
}


def standards_mapping(profile_id: str, command_id: str) -> dict[str, str]:
    if profile_id in API_RISKS:
        reference_id, relationship = API_RISKS[profile_id]
        return {
            "source_id": "owasp-api-security",
            "source_version": "2023",
            "reference_id": reference_id,
            "relationship": relationship,
            "rationale": (
                "The specialist focus directly owns or materially supports this OWASP "
                "API Security risk, as expressed by the relationship field."
            ),
        }
    if profile_id in AGENTIC_RISKS:
        reference_id, relationship = AGENTIC_RISKS[profile_id]
        return {
            "source_id": "owasp-agentic",
            "source_version": "2026",
            "reference_id": reference_id,
            "relationship": relationship,
            "rationale": (
                "The specialist focus directly owns or materially supports this OWASP "
                "Agentic risk, as expressed by the relationship field."
            ),
        }
    if command_id == "AOE-GD-D20":
        return {
            "source_id": "nist-ai-100-2e2025",
            "source_version": "2025",
            "reference_id": NIST_AI_CATEGORIES.get(
                profile_id,
                "attack-category:misuse",
            ),
            "relationship": "related_technique",
            "rationale": (
                "The NIST adversarial machine-learning taxonomy provides the closest "
                "reviewed attack category; a narrower crosswalk remains future work."
            ),
        }
    return {
        "source_id": "mitre-attack",
        "source_version": "19.2",
        "reference_id": COMMAND_TACTICS[command_id],
        "relationship": "contextual_tactic",
        "rationale": (
            "This tactic establishes operational context only and is not claimed as an "
            "exact ATT&CK technique mapping."
        ),
    }


def validator_for(command_id: str) -> str:
    if command_id in {"AOE-GD-D18", "AOE-GD-D19", "AOE-GD-D24", "AOE-GD-D25"}:
        return "AOE-HQ-33"
    if command_id == "AOE-GD-D20":
        return "AOE-HQ-35"
    if command_id in {"AOE-GB-D05", "AOE-GB-D06", "AOE-GB-D07"}:
        return "AOE-HQ-34"
    return "AOE-HQ-19"


def tier_prefix(maximum: str) -> list[str]:
    tiers = ["R0", "R1", "R2", "R3", "R4", "R5"]
    return tiers[: tiers.index(maximum) + 1]


def build_catalog(registry: dict[str, Any], roadmap: dict[str, Any]) -> dict[str, Any]:
    profiles = registry["profiles"]
    specialists = [item for item in profiles if item["kind"] == "specialist"]
    specialists_by_command: dict[str, list[str]] = {}
    for profile in specialists:
        specialists_by_command.setdefault(profile["command_id"], []).append(profile["id"])
    for profile_ids in specialists_by_command.values():
        profile_ids.sort()

    vectors: list[dict[str, Any]] = []
    exact_mapping_count = 0
    for profile in sorted(specialists, key=lambda item: item["id"]):
        command_id = profile["command_id"]
        peers = specialists_by_command[command_id]
        index = peers.index(profile["id"])
        supporters = [
            peers[(index - 1) % len(peers)],
            peers[(index + 1) % len(peers)],
        ]
        mapping = standards_mapping(profile["id"], command_id)
        exact_mapping_count += mapping["relationship"] == "exact_risk"
        vectors.append(
            {
                "vector_id": "AV-" + profile["id"].removeprefix("AOE-") + "-01",
                "name": profile["name"],
                "vector_kind": "specialist_coverage_anchor",
                "description": profile["mission"],
                "standards_mappings": [mapping],
                "platforms_and_protocols": [
                    f"Command domain: {profile['category']}",
                    f"Specialist surface: {profile['name']}",
                ],
                "primary_specialist_id": profile["id"],
                "supporting_specialist_ids": supporters,
                "independent_validator_id": validator_for(command_id),
                "prerequisites_and_observations": [
                    "Exact authorized target and scope binding are available.",
                    "A reproducible baseline and relevant observable signals are available.",
                    "The proposed action tier and stop conditions are explicit.",
                ],
                "allowed_action_tiers": tier_prefix(profile["max_autonomous_tier"]),
                "tools_and_credentials": [
                    "Provider-neutral specialist tool adapter selected by policy.",
                    "Mission-scoped credentials are supplied only when the vector requires them.",
                ],
                "expected_evidence": [
                    "Target, scope, method, timestamp, and tool provenance.",
                    "Reproducible positive or negative observations with integrity metadata.",
                    "Impact bounds, uncertainty, limitations, and supporting handoff records.",
                ],
                "cleanup_and_restoration": [
                    "Remove or account for temporary artifacts created by the approved action.",
                    "Revoke or return mission credentials and access paths.",
                    "Reconcile target state and residual effects with AOE-HQ-33 before closure.",
                ],
                "qualification_scenario_id": f"qualification.{profile['id'].lower()}",
                "known_blind_spots": [
                    "This coverage anchor does not enumerate every product-specific technique.",
                    "Contextual mappings are not exact technique claims.",
                    "Provider, version, deployment, and target-specific gaps require mission review.",
                ],
            }
        )

    body = {
        "schema_version": 1,
        "catalog_id": "sunderkey-attack-vectors-v2",
        "catalog_version": "2.0.0",
        "expert_catalog_id": registry["catalog_id"],
        "expert_catalog_version": registry["catalog_version"],
        "roadmap_id": roadmap["roadmap_id"],
        "roadmap_sha256": roadmap["roadmap_sha256"],
        "catalog_status": "coverage_anchor_baseline",
        "operational_effect": "none",
        "standards_sources": roadmap["standards_sources"],
        "vectors": vectors,
        "coverage_summary": {
            "vector_count": len(vectors),
            "primary_specialist_count": len(vectors),
            "specialists_without_primary_vector": 0,
            "vectors_with_supporting_specialists": len(vectors),
            "vectors_with_external_mapping": len(vectors),
            "exact_external_mapping_count": exact_mapping_count,
        },
        "limitations": [
            "Coverage anchors establish ownership and evidence contracts, not exhaustive technique enumeration.",
            "Contextual tactic mappings must not be presented as exact ATT&CK technique mappings.",
            "Product, version, provider, protocol, and deployment-specific vectors require later additive records.",
            "Catalog inclusion does not qualify a specialist or authorize routing, execution, or deployment.",
        ],
    }
    body["catalog_sha256"] = _canonical_sha256({"domain": CATALOG_DOMAIN, "catalog": body})
    return body


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TypeError(f"Expected an object in {path}")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument("--roadmap", type=Path, default=DEFAULT_ROADMAP)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    registry_document = load_json(args.registry)
    roadmap_document = load_json(args.roadmap)
    document = build_catalog(registry_document, roadmap_document)
    registry = load_registry(args.registry)
    roadmap = load_army_expansion_roadmap(args.roadmap)
    catalog = AttackVectorCatalog.from_dict(document, registry, roadmap)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(catalog.to_dict(), ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(
        json.dumps(
            {
                "catalog_id": document["catalog_id"],
                "catalog_sha256": catalog.catalog_sha256,
                **catalog.coverage_summary,
                "operational_effect": "none",
                "status": "valid",
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

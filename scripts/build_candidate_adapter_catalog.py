"""Build the Phase 157 cross-domain reference adapter catalog."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from sunderkey.army_expansion import load_army_expansion_roadmap
from sunderkey.attack_vectors import load_attack_vector_catalog
from sunderkey.candidate_adapter_sdk import (
    REFERENCE_PROFILES,
    SOURCE_PATH,
    build_candidate_adapter_catalog,
)
from sunderkey.candidate_blueprints_v2 import load_candidate_blueprint_catalog_v2
from sunderkey.candidate_implementation_strategy import load_candidate_implementation_strategy
from sunderkey.qualification import load_qualification_standard
from sunderkey.qualification_plans_v2 import load_qualification_plan_catalog_v2
from sunderkey.registry import load_registry
from sunderkey.routing import load_capability_catalog

ROOT = Path(__file__).resolve().parents[1]
REGISTRY_DIR = ROOT / "registry"
STRATEGY_PATH = REGISTRY_DIR / "candidate-implementation-strategy-v1.json"
BLUEPRINTS_PATH = REGISTRY_DIR / "candidate-blueprints-army-v2.json"
OUTPUT_PATH = REGISTRY_DIR / "candidate-adapters-reference-v1.json"
SCHEMA_PATH = REGISTRY_DIR / "schemas" / "candidate-adapter-catalog-v1.schema.json"


def load_blueprints():
    registry = load_registry(REGISTRY_DIR / "army-v2.json")
    capabilities = load_capability_catalog(REGISTRY_DIR / "capabilities-army-v2.json", registry)
    roadmap = load_army_expansion_roadmap(REGISTRY_DIR / "army-expansion-roadmap-v1.json")
    vectors = load_attack_vector_catalog(REGISTRY_DIR / "attack-vectors-v2.json", registry, roadmap)
    standard = load_qualification_standard(
        REGISTRY_DIR / "qualification-standard-v2.json", registry, capabilities
    )
    plans = load_qualification_plan_catalog_v2(
        REGISTRY_DIR / "qualification-plans-army-v2.json",
        registry,
        capabilities,
        vectors,
        standard,
    )
    return load_candidate_blueprint_catalog_v2(
        BLUEPRINTS_PATH, registry, capabilities, vectors, standard, plans
    )


def build_schema() -> dict[str, Any]:
    text = {"type": "string", "minLength": 1, "pattern": r"^[\t\n\r -~]*[!-~][\t\n\r -~]*$"}
    sha = {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}
    effects = {
        "qualification_effect": {"const": "none"},
        "routing_effect": {"const": "none"},
        "execution_effect": {"const": "none"},
        "deployment_effect": {"const": "none"},
    }
    top_fields = [
        "schema_version",
        "catalog_id",
        "catalog_version",
        "catalog_sha256",
        "strategy_id",
        "strategy_sha256",
        "blueprint_catalog_sha256",
        "development_mode",
        "reference_slice",
        "manifests",
        "coverage_summary",
        *effects,
        "limitations",
    ]
    manifest_fields = [
        "adapter_id",
        "adapter_version",
        "profile_id",
        "profile_name",
        "vector_id",
        "blueprint_sha256",
        "primary_capability_id",
        "reference_role",
        "implementation",
        "source_provenance",
        "runtime",
        "resource_policy",
        "contracts",
        "hooks",
        "evidence_semantics",
        "known_limitations",
        "implementation_status",
        *effects,
        "manifest_sha256",
    ]
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://schemas.sunderkey.dev/candidate-adapter-catalog-v1.json",
        "title": "SUNDERKEY Candidate Adapter Reference Catalog",
        "type": "object",
        "additionalProperties": False,
        "required": top_fields,
        "properties": {
            "schema_version": {"const": 1},
            "catalog_id": {"const": "sunderkey-candidate-adapters-v1"},
            "catalog_version": {"const": "0.1.0"},
            "catalog_sha256": sha,
            "strategy_id": {"type": "string", "pattern": "^CIS-[0-9A-F]{32}$"},
            "strategy_sha256": sha,
            "blueprint_catalog_sha256": sha,
            "development_mode": {"const": "offline_synthetic_only"},
            "reference_slice": {
                "type": "array",
                "prefixItems": [{"const": item[0]} for item in REFERENCE_PROFILES],
                "items": False,
            },
            "manifests": {
                "type": "array",
                "minItems": 6,
                "maxItems": 6,
                "items": {"$ref": "#/$defs/manifest"},
            },
            "coverage_summary": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "reference_adapter_count",
                    "profile_count",
                    "oci_required_count",
                    "microvm_required_count",
                    "deny_all_resource_policy_count",
                    "offline_synthetic_only_count",
                ],
                "properties": {
                    "reference_adapter_count": {"const": 6},
                    "profile_count": {"const": 6},
                    "oci_required_count": {"const": 3},
                    "microvm_required_count": {"const": 3},
                    "deny_all_resource_policy_count": {"const": 6},
                    "offline_synthetic_only_count": {"const": 6},
                },
            },
            **effects,
            "limitations": {"$ref": "#/$defs/textList"},
        },
        "$defs": {
            "text": text,
            "sha": sha,
            "textList": {
                "type": "array",
                "minItems": 1,
                "uniqueItems": True,
                "items": {"$ref": "#/$defs/text"},
            },
            "denyList": {"type": "array", "maxItems": 0},
            "manifest": {
                "type": "object",
                "additionalProperties": False,
                "required": manifest_fields,
                "properties": {
                    "adapter_id": {
                        "type": "string",
                        "pattern": "^adapter\\.aoe-g[a-e]-d[0-9]{2}-s[0-9]{2}\\.[a-z0-9-]+$",
                    },
                    "adapter_version": {"const": "0.1.0"},
                    "profile_id": {"type": "string", "pattern": "^AOE-G[A-E]-D[0-9]{2}-S[0-9]{2}$"},
                    "profile_name": text,
                    "vector_id": {
                        "type": "string",
                        "pattern": "^AV-G[A-E]-D[0-9]{2}-S[0-9]{2}-01$",
                    },
                    "blueprint_sha256": sha,
                    "primary_capability_id": text,
                    "reference_role": {"enum": [item[1] for item in REFERENCE_PROFILES]},
                    "implementation": {"const": "reference_adapter"},
                    "source_provenance": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": [
                            "kind",
                            "repository_path",
                            "source_sha256",
                            "license",
                            "external_dependencies",
                        ],
                        "properties": {
                            "kind": {"const": "sunderkey_native_python"},
                            "repository_path": {"const": SOURCE_PATH},
                            "source_sha256": sha,
                            "license": {"const": "LicenseRef-SUNDERKEY-All-Rights-Reserved"},
                            "external_dependencies": {"$ref": "#/$defs/denyList"},
                        },
                    },
                    "runtime": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": [
                            "language",
                            "initial_host",
                            "required_isolation",
                            "development_mode",
                            "maximum_action_tier",
                        ],
                        "properties": {
                            "language": {"const": "python_3_11_or_newer"},
                            "initial_host": {"const": "linux"},
                            "required_isolation": {"enum": ["oci_container", "microvm"]},
                            "development_mode": {"const": "offline_synthetic_only"},
                            "maximum_action_tier": {"const": "R0"},
                        },
                    },
                    "resource_policy": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["network", "filesystem", "process", "credential"],
                        "properties": {
                            name: {"$ref": "#/$defs/denyList"}
                            for name in ("network", "filesystem", "process", "credential")
                        },
                    },
                    "contracts": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": ["input", "output", "evidence", "restoration"],
                        "properties": {
                            name: {"type": "string", "pattern": "^sunderkey://"}
                            for name in ("input", "output", "evidence", "restoration")
                        },
                    },
                    "hooks": {
                        "type": "object",
                        "additionalProperties": False,
                        "required": [
                            "dry_run",
                            "timeout",
                            "cancellation",
                            "rate_limit",
                            "structured_evidence",
                            "cleanup_result",
                        ],
                        "properties": {
                            name: {"const": True}
                            for name in (
                                "dry_run",
                                "timeout",
                                "cancellation",
                                "rate_limit",
                                "structured_evidence",
                                "cleanup_result",
                            )
                        },
                    },
                    "evidence_semantics": {"$ref": "#/$defs/textList"},
                    "known_limitations": {"$ref": "#/$defs/textList"},
                    "implementation_status": {"const": "sdk_bound_pending_qualification"},
                    **effects,
                    "manifest_sha256": sha,
                },
            },
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=OUTPUT_PATH)
    parser.add_argument("--schema-output", type=Path, default=SCHEMA_PATH)
    args = parser.parse_args()
    strategy = load_candidate_implementation_strategy(STRATEGY_PATH)
    blueprints = load_blueprints()
    source_sha256 = "sha256:" + hashlib.sha256((ROOT / SOURCE_PATH).read_bytes()).hexdigest()
    catalog = build_candidate_adapter_catalog(strategy, blueprints, source_sha256)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.schema_output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(catalog.to_dict(), ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    args.schema_output.write_text(
        json.dumps(build_schema(), ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(
        json.dumps(
            {
                "catalog_sha256": catalog.catalog_sha256,
                "reference_adapter_count": len(catalog.manifests),
                "status": "valid",
                "operational_effect": "none",
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

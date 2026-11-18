"""Build the deterministic provider-neutral candidate catalog fixture."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

PROFILE_ID = "AOE-GA-D01-S01"
CANDIDATE_ID = "fixture.passive-osint"
CANDIDATE_VERSION = "1.0.0"
CANDIDATE_ARTIFACT_DOMAIN = "sunderkey.candidate-implementation.v1"


def build_parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(
        description="Build the provider-neutral candidate catalog fixture"
    )
    parser.add_argument(
        "--registry",
        default=str(root / "registry" / "army-v1.json"),
    )
    parser.add_argument(
        "--capabilities",
        default=str(root / "registry" / "capabilities-army-v1.json"),
    )
    parser.add_argument(
        "--standard",
        default=str(root / "registry" / "qualification-standard-v1.json"),
    )
    parser.add_argument(
        "--plans",
        default=str(
            root / "registry" / "qualification-plans-army-v1.json"
        ),
    )
    parser.add_argument(
        "--blueprints",
        default=str(
            root / "registry" / "candidate-blueprints-army-v1.json"
        ),
    )
    parser.add_argument(
        "--components",
        default=str(root / "registry" / "candidate-components-v1.json"),
    )
    parser.add_argument(
        "--output",
        default=str(
            root / "registry" / "candidate-implementations-v1.json"
        ),
    )
    return parser


def _read_json(path: str) -> dict[str, Any]:
    resolved = Path(path).resolve()
    value = json.loads(resolved.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"Expected a JSON object: {resolved}")
    return value


def _canonical_sha256(value: Any) -> str:
    payload = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def _candidate_artifact_sha256(body: dict[str, Any]) -> str:
    return _canonical_sha256(
        {
            "domain": CANDIDATE_ARTIFACT_DOMAIN,
            "candidate": body,
        }
    )


def build_catalog(
    registry: dict[str, Any],
    capabilities: dict[str, Any],
    standard: dict[str, Any],
    plans: dict[str, Any],
    blueprints: dict[str, Any],
    components: dict[str, Any],
) -> dict[str, Any]:
    if not any(
        item["id"] == PROFILE_ID for item in registry["profiles"]
    ):
        raise ValueError("Passive OSINT profile is missing")
    plan = next(
        item
        for item in plans["profile_plans"]
        if item["profile_id"] == PROFILE_ID
    )
    blueprint = next(
        item
        for item in blueprints["blueprints"]
        if item["profile_id"] == PROFILE_ID
    )
    candidate_components = {
        item["component_type"]: item
        for item in components["components"]
        if item["candidate_id"] == CANDIDATE_ID
        and item["candidate_version"] == CANDIDATE_VERSION
    }
    if set(candidate_components) != {
        "behavior_contract",
        "instruction_bundle",
        "knowledge_manifest",
        "runtime_manifest",
        "tool_policy",
    }:
        raise ValueError("Passive OSINT component fixture is incomplete")
    candidate_body = {
        "candidate_id": CANDIDATE_ID,
        "candidate_version": CANDIDATE_VERSION,
        "profile_id": PROFILE_ID,
        "lifecycle": "contract_fixture",
        "implementation_kind": "agent_bundle",
        "candidate_blueprint_sha256": blueprint["blueprint_sha256"],
        "behavior_contract_sha256": candidate_components[
            "behavior_contract"
        ]["component_sha256"],
        "instruction_bundle_sha256": candidate_components[
            "instruction_bundle"
        ]["component_sha256"],
        "knowledge_manifest_sha256": candidate_components[
            "knowledge_manifest"
        ]["component_sha256"],
        "runtime_manifest_sha256": candidate_components[
            "runtime_manifest"
        ]["component_sha256"],
        "tool_policy_sha256": candidate_components["tool_policy"][
            "component_sha256"
        ],
    }
    candidate = {
        **candidate_body,
        "candidate_artifact_sha256": _candidate_artifact_sha256(
            candidate_body
        ),
    }
    if plan["scenario_family_id"] != "qualification.aoe-ga-d01-s01":
        raise ValueError("Passive OSINT scenario family changed")
    return {
        "schema_version": 1,
        "candidate_catalog_id": "sunderkey-specialist-candidates",
        "candidate_catalog_version": "1.0.0",
        "expert_catalog_id": registry["catalog_id"],
        "expert_catalog_version": registry["catalog_version"],
        "capability_catalog_id": capabilities["catalog_id"],
        "capability_catalog_version": capabilities["catalog_version"],
        "capability_catalog_sha256": _canonical_sha256(capabilities),
        "qualification_standard_id": standard["standard_id"],
        "qualification_standard_version": standard["standard_version"],
        "qualification_standard_sha256": _canonical_sha256(standard),
        "qualification_plan_catalog_id": plans["plan_catalog_id"],
        "qualification_plan_catalog_version": plans[
            "plan_catalog_version"
        ],
        "qualification_plan_catalog_sha256": _canonical_sha256(plans),
        "candidate_blueprint_catalog_id": blueprints[
            "blueprint_catalog_id"
        ],
        "candidate_blueprint_catalog_version": blueprints[
            "blueprint_catalog_version"
        ],
        "candidate_blueprint_catalog_sha256": _canonical_sha256(
            blueprints
        ),
        "candidates": [candidate],
    }


def main() -> None:
    args = build_parser().parse_args()
    catalog = build_catalog(
        _read_json(args.registry),
        _read_json(args.capabilities),
        _read_json(args.standard),
        _read_json(args.plans),
        _read_json(args.blueprints),
        _read_json(args.components),
    )
    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(catalog, ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(
        f"Wrote {len(catalog['candidates'])} candidate: {output}"
    )


if __name__ == "__main__":
    main()

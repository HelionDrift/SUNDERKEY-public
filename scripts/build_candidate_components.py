"""Build the deterministic provider-neutral candidate component fixture."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

PROFILE_ID = "AOE-GA-D01-S01"
CANDIDATE_ID = "fixture.passive-osint"
CANDIDATE_VERSION = "1.0.0"
COMPONENT_DOMAIN = "sunderkey.candidate-component.v1"
COMPONENT_TYPES = (
    "behavior_contract",
    "instruction_bundle",
    "knowledge_manifest",
    "runtime_manifest",
    "tool_policy",
)


def build_parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(
        description="Build the provider-neutral candidate component fixture"
    )
    parser.add_argument(
        "--blueprints",
        default=str(
            root / "registry" / "candidate-blueprints-army-v1.json"
        ),
    )
    parser.add_argument(
        "--output",
        default=str(root / "registry" / "candidate-components-v1.json"),
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


def _component_sha256(body: dict[str, Any]) -> str:
    return _canonical_sha256(
        {"domain": COMPONENT_DOMAIN, "component": body}
    )


def _placeholder_sha256(kind: str) -> str:
    return _canonical_sha256(
        {
            "domain": "sunderkey.synthetic-component-placeholder.v1",
            "candidate_id": CANDIDATE_ID,
            "candidate_version": CANDIDATE_VERSION,
            "component": kind,
            "content": "not-implemented",
        }
    )


def _component(
    blueprint: dict[str, Any],
    component_type: str,
    specification: dict[str, Any],
) -> dict[str, Any]:
    component_body = {
        "component_id": (
            f"{CANDIDATE_ID}.{component_type.replace('_', '-')}"
        ),
        "component_version": "1.0.0",
        "candidate_id": CANDIDATE_ID,
        "candidate_version": CANDIDATE_VERSION,
        "profile_id": PROFILE_ID,
        "candidate_blueprint_sha256": blueprint["blueprint_sha256"],
        "component_type": component_type,
        "component_status": "contract_fixture",
        "specification": specification,
    }
    return {
        **component_body,
        "component_sha256": _component_sha256(component_body),
    }


def build_catalog(blueprints: dict[str, Any]) -> dict[str, Any]:
    blueprint = next(
        item
        for item in blueprints["blueprints"]
        if item["profile_id"] == PROFILE_ID
    )
    specifications = {
        "behavior_contract": {
            "mission": blueprint["mission"],
            "allowed_actions": blueprint["allowed_actions"],
            "prohibited_actions": blueprint["prohibited_actions"],
            "stop_conditions": blueprint["stop_conditions"],
            "maximum_autonomous_action_tier": blueprint[
                "maximum_autonomous_action_tier"
            ],
            "minimum_evidence_level": blueprint[
                "minimum_evidence_level"
            ],
        },
        "instruction_bundle": {
            "bundle_format": "synthetic_placeholder",
            "content_sha256": _placeholder_sha256("instruction_bundle"),
            "primary_capability_ids": blueprint[
                "primary_capability_ids"
            ],
            "supporting_capability_ids": blueprint[
                "supporting_capability_ids"
            ],
            "scenario_family_id": blueprint["scenario_family_id"],
            "required_gate_ids": blueprint["required_gate_ids"],
        },
        "knowledge_manifest": {
            "retrieval_mode": "disabled",
            "source_manifest_sha256": _canonical_sha256(
                {
                    "domain": "sunderkey.synthetic-source-manifest.v1",
                    "sources": [],
                }
            ),
            "source_count": 0,
            "reviewed_source_count": 0,
            "rights_review_status": "not_applicable",
            "minimum_evidence_level": blueprint[
                "minimum_evidence_level"
            ],
        },
        "runtime_manifest": {
            "runtime_class": "disabled_fixture",
            "provider_ref": None,
            "model_ref": None,
            "hosting_ref": None,
            "runtime_config_sha256": _placeholder_sha256(
                "runtime_manifest"
            ),
            "execution_enabled": False,
            "network_access": False,
            "process_access": False,
        },
        "tool_policy": {
            "policy_template_id": blueprint["policy_template_id"],
            "allowed_action_ids": blueprint["allowed_actions"],
            "prohibited_action_ids": blueprint["prohibited_actions"],
            "admission_mode": "deny_all",
            "tool_manifest_sha256": _placeholder_sha256("tool_policy"),
            "allowed_tool_count": 0,
            "credential_access": False,
            "target_access": False,
            "network_access": False,
            "execution_allowed": False,
        },
    }
    return {
        "schema_version": 1,
        "component_catalog_id": "sunderkey-candidate-components",
        "component_catalog_version": "1.0.0",
        "candidate_blueprint_catalog_id": blueprints[
            "blueprint_catalog_id"
        ],
        "candidate_blueprint_catalog_version": blueprints[
            "blueprint_catalog_version"
        ],
        "candidate_blueprint_catalog_sha256": _canonical_sha256(
            blueprints
        ),
        "components": [
            _component(blueprint, component_type, specifications[component_type])
            for component_type in COMPONENT_TYPES
        ],
    }


def main() -> None:
    args = build_parser().parse_args()
    catalog = build_catalog(_read_json(args.blueprints))
    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(catalog, ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(f"Wrote {len(catalog['components'])} components: {output}")


if __name__ == "__main__":
    main()

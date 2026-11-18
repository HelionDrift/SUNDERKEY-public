#!/usr/bin/env python3
"""Build closed schemas for the durable expert collaboration workspace."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "registry" / "schemas"


def _closed(required: list[str], properties: dict[str, Any]) -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": required,
        "properties": properties,
    }


def _defs() -> dict[str, Any]:
    return {
        "identifier": {
            "type": "string",
            "pattern": r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$",
        },
        "sha256": {"type": "string", "pattern": r"^sha256:[0-9a-f]{64}$"},
        "profileId": {
            "type": "string",
            "pattern": r"^AOE-(?:G[A-E]-D[0-9]{2}-(?:S[0-9]{2}|CMD)|HQ-[0-9]{2})$",
        },
    }


def workspace_definition_schema() -> dict[str, Any]:
    assignment = _closed(
        [
            "work_id",
            "profile_id",
            "command_id",
            "runtime_pack_id",
            "runtime_pack_sha256",
            "maximum_attempts",
        ],
        {
            "work_id": {"$ref": "#/$defs/identifier"},
            "profile_id": {"$ref": "#/$defs/profileId"},
            "command_id": {"$ref": "#/$defs/identifier"},
            "runtime_pack_id": {"$ref": "#/$defs/identifier"},
            "runtime_pack_sha256": {"$ref": "#/$defs/sha256"},
            "maximum_attempts": {"type": "integer", "minimum": 1, "maximum": 8},
        },
    )
    dependency = _closed(
        ["work_id", "depends_on_work_id"],
        {
            "work_id": {"$ref": "#/$defs/identifier"},
            "depends_on_work_id": {"$ref": "#/$defs/identifier"},
        },
    )
    review = _closed(
        ["work_id", "required", "reviewer_profile_ids", "producer_excluded"],
        {
            "work_id": {"$ref": "#/$defs/identifier"},
            "required": {"type": "boolean"},
            "reviewer_profile_ids": {
                "type": "array",
                "maxItems": 64,
                "uniqueItems": True,
                "items": {"$ref": "#/$defs/profileId"},
            },
            "producer_excluded": {"const": True},
        },
    )
    required = [
        "schema_version",
        "workspace_id",
        "workspace_sha256",
        "tenant_id",
        "mission_id",
        "plan_id",
        "runtime_catalog_id",
        "runtime_catalog_version",
        "runtime_catalog_sha256",
        "target_scope_sha256",
        "authority_snapshot_sha256",
        "evidence_snapshot_sha256",
        "assignments",
        "dependencies",
        "review_requirements",
        "workspace_effect",
        "model_call_performed",
        "network_call_performed",
        "target_action_performed",
        "tool_effect",
        "qualification_effect",
        "authorization_effect",
    ]
    schema = _closed(
        required,
        {
            "schema_version": {"const": 1},
            "workspace_id": {"type": "string", "pattern": r"^EWS-[0-9A-F]{32}$"},
            "workspace_sha256": {"$ref": "#/$defs/sha256"},
            "tenant_id": {"$ref": "#/$defs/identifier"},
            "mission_id": {"$ref": "#/$defs/identifier"},
            "plan_id": {"$ref": "#/$defs/identifier"},
            "runtime_catalog_id": {"$ref": "#/$defs/identifier"},
            "runtime_catalog_version": {"$ref": "#/$defs/identifier"},
            "runtime_catalog_sha256": {"$ref": "#/$defs/sha256"},
            "target_scope_sha256": {"$ref": "#/$defs/sha256"},
            "authority_snapshot_sha256": {"$ref": "#/$defs/sha256"},
            "evidence_snapshot_sha256": {"$ref": "#/$defs/sha256"},
            "assignments": {
                "type": "array",
                "minItems": 1,
                "maxItems": 512,
                "items": assignment,
            },
            "dependencies": {
                "type": "array",
                "maxItems": 4096,
                "items": dependency,
            },
            "review_requirements": {
                "type": "array",
                "minItems": 1,
                "maxItems": 512,
                "items": review,
            },
            "workspace_effect": {"const": "durable_collaboration_only"},
            "model_call_performed": {"const": False},
            "network_call_performed": {"const": False},
            "target_action_performed": {"const": False},
            "tool_effect": {"const": "none"},
            "qualification_effect": {"const": "none"},
            "authorization_effect": {"const": "none"},
        },
    )
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://sunderkey.dev/schemas/expert-workspace-definition-v1.schema.json",
        "$defs": _defs(),
        **schema,
    }


def lease_receipt_schema() -> dict[str, Any]:
    required = [
        "schema_version",
        "lease_id",
        "workspace_id",
        "work_id",
        "attempt_number",
        "fencing_token",
        "envelope_id",
        "acquired_at",
        "expires_at",
        "workspace_revision",
        "automatic_retry_performed",
        "model_call_performed",
        "network_call_performed",
        "tool_effect",
        "authorization_effect",
    ]
    schema = _closed(
        required,
        {
            "schema_version": {"const": 1},
            "lease_id": {"type": "string", "pattern": r"^EWL-[0-9A-F]{32}$"},
            "workspace_id": {"type": "string", "pattern": r"^EWS-[0-9A-F]{32}$"},
            "work_id": {"$ref": "#/$defs/identifier"},
            "attempt_number": {"type": "integer", "minimum": 1, "maximum": 8},
            "fencing_token": {"type": "integer", "minimum": 1},
            "envelope_id": {"type": "string", "pattern": r"^EEE-[0-9A-F]{32}$"},
            "acquired_at": {"type": "integer", "minimum": 0},
            "expires_at": {"type": "integer", "minimum": 1},
            "workspace_revision": {"type": "integer", "minimum": 1},
            "automatic_retry_performed": {"const": False},
            "model_call_performed": {"const": False},
            "network_call_performed": {"const": False},
            "tool_effect": {"const": "none"},
            "authorization_effect": {"const": "none"},
        },
    )
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://sunderkey.dev/schemas/expert-workspace-lease-receipt-v1.schema.json",
        "$defs": _defs(),
        **schema,
    }


def acceptance_receipt_schema() -> dict[str, Any]:
    required = [
        "schema_version",
        "acceptance_id",
        "workspace_id",
        "work_id",
        "attempt_number",
        "fencing_token",
        "product_id",
        "product_sha256",
        "product_type",
        "workspace_revision",
        "workspace_status",
        "review_status",
        "qualification_effect",
        "authorization_effect",
        "tool_effect",
    ]
    schema = _closed(
        required,
        {
            "schema_version": {"const": 1},
            "acceptance_id": {"type": "string", "pattern": r"^EWA-[0-9A-F]{32}$"},
            "workspace_id": {"type": "string", "pattern": r"^EWS-[0-9A-F]{32}$"},
            "work_id": {"$ref": "#/$defs/identifier"},
            "attempt_number": {"type": "integer", "minimum": 1, "maximum": 8},
            "fencing_token": {"type": "integer", "minimum": 1},
            "product_id": {"type": "string", "pattern": r"^EWP-[0-9A-F]{32}$"},
            "product_sha256": {"$ref": "#/$defs/sha256"},
            "product_type": {"$ref": "#/$defs/identifier"},
            "workspace_revision": {"type": "integer", "minimum": 1},
            "workspace_status": {
                "enum": ["active", "products_complete_pending_review", "completed"]
            },
            "review_status": {"const": "not_reviewed"},
            "qualification_effect": {"const": "none"},
            "authorization_effect": {"const": "none"},
            "tool_effect": {"const": "none"},
        },
    )
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://sunderkey.dev/schemas/expert-workspace-acceptance-receipt-v1.schema.json",
        "$defs": _defs(),
        **schema,
    }


def main() -> None:
    outputs = {
        "expert-workspace-definition-v1.schema.json": workspace_definition_schema(),
        "expert-workspace-lease-receipt-v1.schema.json": lease_receipt_schema(),
        "expert-workspace-acceptance-receipt-v1.schema.json": acceptance_receipt_schema(),
    }
    for name, document in outputs.items():
        (SCHEMAS / name).write_text(
            json.dumps(document, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )


if __name__ == "__main__":
    main()

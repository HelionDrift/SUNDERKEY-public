#!/usr/bin/env python3
"""Build the closed Phase 192 semantic completion and retry schema."""

from __future__ import annotations

import json
from dataclasses import fields
from pathlib import Path
from typing import Any

from sunderkey.semantic_completion_retry import (
    BLOCKER_CODES,
    CHANGED_CONDITION_CODES,
    COMPLETION_STATES,
    DISPOSITION_STATES,
    FAILURE_CLASSES,
    REASON_CODES,
    RETRYABLE_FAILURE_CLASSES,
    RetryAuthorizationAuthority,
    RetryAuthorizationReceipt,
    RetryReplayCommit,
    SemanticCompletionAssessment,
    SemanticCompletionEvidence,
    SemanticCompletionRequirements,
)

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "registry" / "schemas" / "semantic-completion-retry-v1.schema.json"
DIGEST_PATTERN = r"^sha256:[0-9a-f]{64}$"
ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$"
UTC_PATTERN = r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"

RECORDS = (
    SemanticCompletionRequirements,
    SemanticCompletionEvidence,
    SemanticCompletionAssessment,
    RetryAuthorizationAuthority,
    RetryReplayCommit,
    RetryAuthorizationReceipt,
)

ARRAY_ENUMS: dict[str, list[str]] = {
    "blocker_codes": sorted(BLOCKER_CODES),
    "changed_condition_codes": sorted(CHANGED_CONDITION_CODES),
    "reason_codes": sorted(REASON_CODES),
}
ENUMS: dict[str, list[str]] = {
    "completion_state": list(COMPLETION_STATES),
    "failure_class": list(FAILURE_CLASSES),
    "independent_review_state": ["accepted", "not_required", "pending", "rejected"],
    "prior_failure_class": sorted(RETRYABLE_FAILURE_CLASSES),
}
ARRAY_IDS = {
    "approval_requirement_ids",
    "cleanup_requirement_ids",
    "dependency_ids",
    "evidence_requirement_ids",
    "lineage_product_ids",
}
DISPOSITION_ARRAYS = {
    "approval_dispositions",
    "cleanup_dispositions",
    "dependency_dispositions",
    "evidence_dispositions",
}
NULLABLE_DIGESTS = {
    "independent_review_record_sha256",
    "previous_retry_receipt_sha256",
    "provider_observation_sha256",
    "work_product_sha256",
}
NULLABLE_IDS = {"previous_retry_receipt_id", "work_product_id"}


def _effects_schema() -> dict[str, Any]:
    names = (
        "action",
        "authorization",
        "budget_mutation",
        "finding",
        "independent_review",
        "provider_call",
        "qualification",
        "retry_execution",
        "target",
        "tools",
    )
    return {
        "type": "object",
        "additionalProperties": False,
        "required": list(names),
        "properties": {name: {"const": "none"} for name in names},
    }


def _disposition_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "additionalProperties": False,
        "required": ["requirement_id", "state", "proof_sha256s"],
        "properties": {
            "requirement_id": {"type": "string", "pattern": ID_PATTERN},
            "state": {"type": "string", "enum": sorted(DISPOSITION_STATES)},
            "proof_sha256s": {
                "type": "array",
                "maxItems": 128,
                "uniqueItems": True,
                "items": {"type": "string", "pattern": DIGEST_PATTERN},
            },
        },
    }


def _property(name: str) -> dict[str, Any]:
    if name == "schema_version":
        return {"type": "integer", "const": 1}
    if name == "effects":
        return _effects_schema()
    if name in ENUMS:
        return {"type": "string", "enum": ENUMS[name]}
    if name in ARRAY_ENUMS:
        return {
            "type": "array",
            "maxItems": 128,
            "uniqueItems": True,
            "items": {"type": "string", "enum": ARRAY_ENUMS[name]},
        }
    if name in ARRAY_IDS:
        return {
            "type": "array",
            "maxItems": 128,
            "uniqueItems": True,
            "items": {"type": "string", "pattern": ID_PATTERN},
        }
    if name in DISPOSITION_ARRAYS:
        return {
            "type": "array",
            "maxItems": 128,
            "items": {"$ref": "#/$defs/RequirementDisposition"},
        }
    if name in NULLABLE_DIGESTS:
        return {"type": ["string", "null"], "pattern": DIGEST_PATTERN}
    if name.endswith("_sha256"):
        return {"type": "string", "pattern": DIGEST_PATTERN}
    if name in NULLABLE_IDS:
        return {"type": ["string", "null"], "pattern": ID_PATTERN}
    if name.endswith("_id") or name == "budget_revision":
        return {"type": "string", "pattern": ID_PATTERN}
    if name.endswith("_at") or name in {"cooldown_until", "expires_at", "valid_from"}:
        return {"type": "string", "pattern": UTC_PATTERN}
    if name in {"attempt_number", "maximum_attempts"}:
        return {"type": "integer", "minimum": 2, "maximum": 10}
    if name.endswith("_tokens") or name.endswith("_micros"):
        return {"type": "integer", "minimum": 1}
    if name in {"independent_review_required", "retry_eligible"}:
        return {"type": "boolean"}
    return {"type": "string", "minLength": 1, "maxLength": 4096}


def semantic_completion_retry_schema() -> dict[str, Any]:
    definitions: dict[str, Any] = {"RequirementDisposition": _disposition_schema()}
    references: list[dict[str, str]] = []
    for record in RECORDS:
        names = [item.name for item in fields(record)]
        if record in {SemanticCompletionAssessment, RetryAuthorizationReceipt}:
            names.append("effects")
        required = ["schema_version", "kind", *names]
        properties = {name: _property(name) for name in required if name != "kind"}
        properties["kind"] = {"const": record.KIND}
        definition = {
            "type": "object",
            "additionalProperties": False,
            "required": required,
            "properties": properties,
        }
        if record is RetryAuthorizationAuthority:
            definition["allOf"] = [
                {
                    "if": {"properties": {"attempt_number": {"const": 2}}},
                    "then": {
                        "properties": {
                            "previous_retry_receipt_id": {"type": "null"},
                            "previous_retry_receipt_sha256": {"type": "null"},
                        }
                    },
                    "else": {
                        "properties": {
                            "previous_retry_receipt_id": {
                                "type": "string",
                                "pattern": ID_PATTERN,
                            },
                            "previous_retry_receipt_sha256": {
                                "type": "string",
                                "pattern": DIGEST_PATTERN,
                            },
                        }
                    },
                }
            ]
        definitions[record.__name__] = definition
        references.append({"$ref": f"#/$defs/{record.__name__}"})
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://sunderkey.local/schemas/semantic-completion-retry-v1.schema.json",
        "title": "SUNDERKEY semantic completion and retry records v1",
        "oneOf": references,
        "$defs": definitions,
    }


def main() -> int:
    SCHEMA_PATH.write_text(
        json.dumps(semantic_completion_retry_schema(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

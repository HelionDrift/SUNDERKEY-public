#!/usr/bin/env python3
"""Build the closed Phase 189 execution-custody record schema."""

from __future__ import annotations

import json
from dataclasses import fields
from pathlib import Path
from typing import Any

from sunderkey.expert_model_execution_custody import (
    ExpertBudgetReservationCommit,
    ExpertBudgetSettlement,
    ExpertExecutionAuthority,
    ExpertInvocationPlan,
    ExpertModelExecutionReceipt,
    ExpertProviderObservation,
)

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "registry" / "schemas" / "expert-model-execution-custody-v1.schema.json"
DIGEST_PATTERN = r"^sha256:[0-9a-f]{64}$"
ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$"
UTC_PATTERN = r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"

RECORDS = (
    ExpertExecutionAuthority,
    ExpertInvocationPlan,
    ExpertBudgetReservationCommit,
    ExpertProviderObservation,
    ExpertBudgetSettlement,
    ExpertModelExecutionReceipt,
)

ENUMS: dict[str, list[Any]] = {
    "execution_state": [
        "completed_settled",
        "provider_failed_settled",
        "incomplete_settled",
        "indeterminate_quarantined",
    ],
    "output_status": [
        "parsed_advisory_work_product",
        "no_output",
        "malformed_output",
        "referenced_output_not_parsed",
        "indeterminate",
    ],
    "reservation_state": ["committed"],
    "response_contract": ["closed_expert_work_product_v1"],
    "untrusted_text_policy": ["data_only_never_instruction"],
    "usage_basis": ["trusted_actual", "full_reservation"],
}

NULLABLE_DIGESTS = {"provider_observation_sha256", "work_product_sha256"}
NULLABLE_IDS = {"provider_observation_id", "work_product_id"}
NULLABLE_INTEGERS = {"input_tokens", "output_tokens", "billable_cost_micros"}


POSITIVE_INTEGERS = {
    "cost_ceiling_micros",
    "input_token_ceiling",
    "maximum_cost_micros",
    "maximum_input_tokens",
    "maximum_output_tokens",
    "maximum_route_age_seconds",
    "output_token_ceiling",
}


def _property(record: type[Any], name: str) -> dict[str, Any]:
    if name in ENUMS:
        return {"type": "string", "enum": ENUMS[name]}
    if name == "schema_version":
        return {"const": 1}
    if name == "kind":
        raise AssertionError("kind is set per record")
    if name == "effects":
        names = (
            "action",
            "authorization",
            "finding",
            "independent_review",
            "qualification",
            "target",
            "tools",
        )
        return {
            "type": "object",
            "additionalProperties": False,
            "required": list(names),
            "properties": {item: {"const": "none"} for item in names},
        }
    if name in NULLABLE_DIGESTS:
        return {"type": ["string", "null"], "pattern": DIGEST_PATTERN}
    if name.endswith("_sha256"):
        return {"type": "string", "pattern": DIGEST_PATTERN}
    if name in NULLABLE_IDS:
        return {"type": ["string", "null"], "pattern": ID_PATTERN}
    if name.endswith("_id") or name in {
        "budget_revision_before",
        "budget_revision_after",
        "provider_api_version",
        "model_version",
        "pricing_revision",
    }:
        return {"type": "string", "pattern": ID_PATTERN}
    if name.endswith("_at") or name in {"valid_from", "expires_at"}:
        return {"type": "string", "pattern": UTC_PATTERN}
    if name in NULLABLE_INTEGERS:
        return {"type": ["integer", "null"], "minimum": 0}
    if name in POSITIVE_INTEGERS:
        return {"type": "integer", "minimum": 1}
    if name.endswith("_tokens") or name.endswith("_micros") or name.endswith("_seconds"):
        return {"type": "integer", "minimum": 0}
    if name in {"maximum_request_count", "request_count"}:
        return {"const": 1}
    if name == "tools_enabled":
        return {"const": False}
    if name in {"usage_trustworthy", "quarantined"}:
        return {"type": "boolean"}
    if name == "incomplete_reason":
        return {
            "type": ["string", "null"],
            "minLength": 1,
            "maxLength": 1024,
            "pattern": r"^[\t\n\r\u0020-\u007E]+$",
        }
    if name == "structured_output_json":
        return {"type": ["string", "null"], "maxLength": 131072}
    if name == "structured_output_reference":
        return {"type": ["string", "null"], "pattern": DIGEST_PATTERN}
    if name == "credential_reference":
        return {
            "type": "string",
            "pattern": r"^ref:[A-Za-z0-9][A-Za-z0-9._:/-]{2,251}$",
            "maxLength": 255,
        }
    if name == "terminal_state":
        values = (
            ["completed", "incomplete", "failed"]
            if record is ExpertProviderObservation
            else [
                "completed_settled",
                "provider_failed_settled",
                "incomplete_settled",
                "indeterminate_quarantined",
            ]
        )
        return {"type": "string", "enum": values}
    if name == "trusted_runtime_instructions":
        return {"type": "object"}
    if name == "untrusted_context":
        return {"type": "array", "maxItems": 48, "items": {"type": "object"}}
    return {"type": "string", "minLength": 1, "maxLength": 4096}


def execution_custody_schema() -> dict[str, Any]:
    definitions: dict[str, Any] = {}
    references: list[dict[str, str]] = []
    for record in RECORDS:
        record_name = record.__name__
        names = [item.name for item in fields(record)]
        if record is ExpertModelExecutionReceipt:
            names.append("effects")
        required = ["schema_version", "kind", *names]
        properties = {name: _property(record, name) for name in required if name != "kind"}
        properties["kind"] = {"const": record.KIND}
        definitions[record_name] = {
            "type": "object",
            "additionalProperties": False,
            "required": required,
            "properties": properties,
        }
        references.append({"$ref": f"#/$defs/{record_name}"})
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://sunderkey.local/schemas/expert-model-execution-custody-v1.schema.json",
        "title": "SUNDERKEY expert model execution custody records v1",
        "oneOf": references,
        "$defs": definitions,
    }


def main() -> int:
    SCHEMA_PATH.write_text(
        json.dumps(execution_custody_schema(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Build the closed Phase196 authenticated action execution schema."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "registry/schemas/authenticated-action-execution-v1.schema.json"

IDENTIFIER = {"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9._:/-]{2,255}$"}
SHA256 = {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}
TIMESTAMP = {
    "type": "string",
    "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$",
}
RESOURCE_FIELDS = (
    "money_microunits",
    "rate_units",
    "request_bytes",
    "response_bytes",
    "duration_ms",
    "impact_events",
)
AUTHORITY_CHECKS = (
    "adapter_qualified",
    "admission_current",
    "admission_unrevoked",
    "budget_current",
    "catalog_current",
    "cleanup_ready",
    "credential_current",
    "evidence_ready",
    "fence_current",
    "health_current",
    "lease_current",
    "mission_active",
    "plan_current",
    "scope_current",
    "session_current",
    "stop_ready",
    "trust_current",
)
ADAPTER_FIELDS = (
    "adapter_id",
    "adapter_kind",
    "adapter_version",
    "adapter_build_sha256",
    "deployment_binding_sha256",
)
AUTHORIZATION_FIELDS = (
    "operation",
    "principal_profile_id",
    "principal_subject",
    "assertion_issuer",
    "assertion_id",
    "assertion_sha256",
    "assertion_key_sha256",
    "trust_policy_sha256",
    "scope_grant_sha256",
    "operation_intent_sha256",
    "canonical_replay_key_sha256",
    "tenant_id",
    "mission_id",
    "scope_sha256",
    "target_sha256",
    "action_sha256",
    "receipt_sha256",
    "request_sha256",
    "decision",
    "issued_at",
    "expires_at",
)
ADMISSION_AUTHORIZATION_FIELDS = (
    "role",
    "principal_profile_id",
    "principal_subject",
    "assertion_issuer",
    "assertion_id",
    "assertion_sha256",
    "assertion_key_sha256",
    "trust_policy_sha256",
    "scope_grant_sha256",
    "operation_intent_sha256",
    "canonical_replay_key_sha256",
    "tenant_id",
    "mission_id",
    "scope_sha256",
    "target_sha256",
    "action_sha256",
    "resolution_sha256",
    "authorized_tier",
    "decision",
    "issued_at",
    "expires_at",
)
EFFECT_FIELDS = (
    "authorization_effect",
    "dispatch_performed",
    "model_call_performed",
    "network_call_performed",
    "qualification_effect",
    "target_action_performed",
    "tool_effect",
)


def _closed(fields: tuple[str, ...]) -> dict[str, Any]:
    return {
        "type": "object",
        "required": list(fields),
        "properties": {field: {"type": "string"} for field in fields},
        "additionalProperties": False,
    }


def build_schema() -> dict[str, Any]:
    strict_object = {
        "type": "object",
        "maxProperties": 4096,
        "propertyNames": {"pattern": "^[\\x20-\\x7e]+$"},
        "additionalProperties": {"$ref": "#/$defs/strict_value"},
    }
    strict_value = {
        "oneOf": [
            {"type": "null"},
            {"type": "boolean"},
            {"type": "integer", "minimum": -(2**63), "maximum": 2**63 - 1},
            {"type": "string", "pattern": "^[\\x20-\\x7e]*$", "maxLength": 8_388_608},
            {
                "type": "array",
                "maxItems": 4096,
                "items": {"$ref": "#/$defs/strict_value"},
            },
            {"$ref": "#/$defs/strict_object"},
        ]
    }
    resources = _closed(RESOURCE_FIELDS)
    resources["properties"] = {
        field: {"type": "integer", "minimum": 0, "maximum": 2**63 - 1}
        for field in RESOURCE_FIELDS
    }
    positive_resources = _closed(RESOURCE_FIELDS)
    positive_resources["properties"] = {
        field: {
            "type": "integer",
            "minimum": 0 if field == "money_microunits" else 1,
            "maximum": 2**63 - 1,
        }
        for field in RESOURCE_FIELDS
    }
    adapter = _closed(ADAPTER_FIELDS)
    adapter["properties"]["adapter_id"] = IDENTIFIER
    adapter["properties"]["adapter_kind"] = {
        "enum": ["http", "browser", "session", "specialist"]
    }
    adapter["properties"]["adapter_version"] = IDENTIFIER
    adapter["properties"]["adapter_build_sha256"] = SHA256
    adapter["properties"]["deployment_binding_sha256"] = SHA256
    adapter_result_fields = (
        "request_id",
        "request_sha256",
        "action_sha256",
        "adapter",
        "outcome",
        "evidence_status",
        "cleanup_status",
        "restoration_status",
        "result_payload",
        "resources_used",
    )
    adapter_result = _closed(adapter_result_fields)
    adapter_result["properties"].update(
        {
            "request_id": IDENTIFIER,
            "request_sha256": SHA256,
            "action_sha256": SHA256,
            "adapter": {"$ref": "#/$defs/adapter"},
            "outcome": {"enum": ["succeeded", "failed"]},
            "evidence_status": {
                "enum": ["complete", "pending", "failed", "unknown"]
            },
            "cleanup_status": {
                "enum": ["complete", "pending", "failed", "unknown"]
            },
            "restoration_status": {
                "enum": ["complete", "pending", "failed", "unknown"]
            },
            "result_payload": {"$ref": "#/$defs/strict_object"},
            "resources_used": {"$ref": "#/$defs/positive_resources"},
        }
    )
    quarantine_result = _closed(("reason_code", "trusted_result"))
    quarantine_result["properties"].update(
        {"reason_code": IDENTIFIER, "trusted_result": {"const": False}}
    )
    checks = _closed(AUTHORITY_CHECKS)
    checks["properties"] = {field: {"const": True} for field in AUTHORITY_CHECKS}
    state_fields = (
        "tenant_id",
        "mission_id",
        "plan_id",
        "scope_sha256",
        "target_sha256",
        "action_sha256",
        "receipt_id",
        "receipt_sha256",
        "review_evidence_sha256",
        "catalog_id",
        "catalog_sha256",
        "catalog_version",
        "catalog_authority_sha256",
        "authority_revision_sha256",
        "checks",
    )
    state = _closed(state_fields)
    for field in (
        "tenant_id",
        "mission_id",
        "plan_id",
        "receipt_id",
        "catalog_id",
        "catalog_version",
    ):
        state["properties"][field] = IDENTIFIER
    for field in (
        "scope_sha256",
        "target_sha256",
        "action_sha256",
        "receipt_sha256",
        "review_evidence_sha256",
        "catalog_sha256",
        "catalog_authority_sha256",
        "authority_revision_sha256",
    ):
        state["properties"][field] = SHA256
    state["properties"]["checks"] = {"$ref": "#/$defs/authority_checks"}
    authorization = _closed(AUTHORIZATION_FIELDS)
    authorization["properties"]["operation"] = {
        "const": "sunderkey.action.execute.v1"
    }
    authorization["properties"]["role"] = {"const": "admission_control"}
    authorization["required"].append("role")
    authorization["required"].sort()
    authorization["properties"]["decision"] = {"const": "approved"}
    for field in (
        "principal_profile_id",
        "principal_subject",
        "assertion_issuer",
        "assertion_id",
        "tenant_id",
        "mission_id",
    ):
        authorization["properties"][field] = IDENTIFIER
    for field in AUTHORIZATION_FIELDS:
        if field.endswith("_sha256"):
            authorization["properties"][field] = SHA256
    authorization["properties"]["issued_at"] = TIMESTAMP
    authorization["properties"]["expires_at"] = TIMESTAMP
    admission_authorization = _closed(ADMISSION_AUTHORIZATION_FIELDS)
    admission_authorization["properties"].update(
        {
            "role": {
                "enum": [
                    "typed_resolver",
                    "mission_owner",
                    "independent_control",
                    "admission_control",
                ]
            },
            "authorized_tier": {"enum": ["R0", "R1", "R2", "R3", "R4"]},
            "decision": {"const": "approved"},
            "issued_at": TIMESTAMP,
            "expires_at": TIMESTAMP,
        }
    )
    for field in (
        "principal_profile_id",
        "principal_subject",
        "assertion_issuer",
        "assertion_id",
        "tenant_id",
        "mission_id",
    ):
        admission_authorization["properties"][field] = IDENTIFIER
    for field in ADMISSION_AUTHORIZATION_FIELDS:
        if field.endswith("_sha256"):
            admission_authorization["properties"][field] = SHA256
    effects = _closed(EFFECT_FIELDS)
    effects["properties"] = {
        "authorization_effect": {"const": "none"},
        "dispatch_performed": {"const": False},
        "model_call_performed": {"const": False},
        "network_call_performed": {"const": False},
        "qualification_effect": {"const": "none"},
        "target_action_performed": {"const": False},
        "tool_effect": {"const": "none"},
    }
    receipt_fields = (
        "schema_version",
        "kind",
        "receipt_id",
        "receipt_sha256",
        "resolution_id",
        "resolution_sha256",
        "quorum_id",
        "quorum_sha256",
        "request_id",
        "request_sha256",
        "decision_id",
        "decision_sha256",
        "tenant_id",
        "mission_id",
        "scope_sha256",
        "target_sha256",
        "action_sha256",
        "action_tier",
        "evaluated_at",
        "status",
        "admission_authorization",
        "identity_assurance",
        "effects",
    )
    receipt = _closed(receipt_fields)
    receipt["properties"].update(
        {
            "schema_version": {"const": 1},
            "kind": {"const": "authenticated_action_admission_receipt"},
            "action_tier": {"enum": ["R0", "R1", "R2", "R3", "R4"]},
            "evaluated_at": TIMESTAMP,
            "status": {"const": "admitted_contract_only"},
            "admission_authorization": {"$ref": "#/$defs/admission_authorization"},
            "identity_assurance": {"const": "mission_store_principal_assertion"},
            "effects": {"$ref": "#/$defs/effects"},
        }
    )
    for field in (
        "receipt_id",
        "resolution_id",
        "quorum_id",
        "request_id",
        "decision_id",
        "tenant_id",
        "mission_id",
    ):
        receipt["properties"][field] = IDENTIFIER
    for field in receipt_fields:
        if field.endswith("_sha256"):
            receipt["properties"][field] = SHA256

    request_fields = (
        "schema_version",
        "kind",
        "action_execution_request_id",
        "action_execution_request_sha256",
        "command_sha256",
        "idempotency_key_sha256",
        "admission_receipt",
        "admission_custody_sha256",
        "authority_state",
        "authority_state_sha256",
        "adapter",
        "adapter_input",
        "adapter_input_sha256",
        "budget_id",
        "budget_sha256",
        "reservation",
        "prepared_at",
        "execution_status",
    )
    request = _closed(request_fields)
    request["properties"].update(
        {
            "schema_version": {"const": 1},
            "kind": {"const": "action_execution_request"},
            "action_execution_request_id": IDENTIFIER,
            "action_execution_request_sha256": SHA256,
            "command_sha256": SHA256,
            "idempotency_key_sha256": SHA256,
            "admission_receipt": {"$ref": "#/$defs/admission_receipt"},
            "admission_custody_sha256": SHA256,
            "authority_state": {"$ref": "#/$defs/authority_state"},
            "authority_state_sha256": SHA256,
            "adapter": {"$ref": "#/$defs/adapter"},
            "adapter_input": {"$ref": "#/$defs/strict_object"},
            "adapter_input_sha256": SHA256,
            "budget_id": IDENTIFIER,
            "budget_sha256": SHA256,
            "reservation": {"$ref": "#/$defs/positive_resources"},
            "prepared_at": TIMESTAMP,
            "execution_status": {"const": "reserved_pending_adapter"},
        }
    )
    claim_fields = (
        "schema_version",
        "kind",
        "action_execution_claim_id",
        "action_execution_claim_sha256",
        "request_id",
        "request_sha256",
        "authorization",
        "claimed_at",
        "claim_status",
    )
    claim = _closed(claim_fields)
    claim["properties"].update(
        {
            "schema_version": {"const": 1},
            "kind": {"const": "action_execution_claim"},
            "action_execution_claim_id": IDENTIFIER,
            "action_execution_claim_sha256": SHA256,
            "request_id": IDENTIFIER,
            "request_sha256": SHA256,
            "authorization": {"$ref": "#/$defs/authorization"},
            "claimed_at": TIMESTAMP,
            "claim_status": {"const": "claimed_pending_dispatch"},
        }
    )
    terminal_fields = (
        "schema_version",
        "kind",
        "action_execution_terminal_id",
        "action_execution_terminal_sha256",
        "request_id",
        "request_sha256",
        "claim_id",
        "claim_sha256",
        "terminal_status",
        "action_outcome",
        "evidence_status",
        "cleanup_status",
        "restoration_status",
        "result_sha256",
        "result_document",
        "charged_resources",
        "reason_code",
        "settled_at",
        "adapter_call_count",
        "adapter_call_count_status",
        "automatic_retry_count",
    )
    terminal = _closed(terminal_fields)
    terminal["properties"].update(
        {
            "schema_version": {"const": 1},
            "kind": {"const": "action_execution_terminal"},
            "action_execution_terminal_id": IDENTIFIER,
            "action_execution_terminal_sha256": SHA256,
            "request_id": IDENTIFIER,
            "request_sha256": SHA256,
            "claim_id": IDENTIFIER,
            "claim_sha256": SHA256,
            "terminal_status": {
                "enum": [
                    "completed",
                    "failed_known",
                    "predispatch_aborted",
                    "indeterminate_quarantined",
                ]
            },
            "action_outcome": {"enum": ["succeeded", "failed", "indeterminate"]},
            "evidence_status": {"enum": ["complete", "pending", "failed", "unknown"]},
            "cleanup_status": {"enum": ["complete", "pending", "failed", "unknown"]},
            "restoration_status": {
                "enum": ["complete", "pending", "failed", "unknown"]
            },
            "result_sha256": SHA256,
            "result_document": {"type": "object"},
            "charged_resources": {"$ref": "#/$defs/resources"},
            "reason_code": IDENTIFIER,
            "settled_at": TIMESTAMP,
            "adapter_call_count": {"type": ["integer", "null"], "minimum": 0, "maximum": 1},
            "adapter_call_count_status": {
                "enum": ["exactly_one", "exactly_zero", "unknown_zero_or_one"]
            },
            "automatic_retry_count": {"const": 0},
        }
    )
    terminal["allOf"] = [
        {
            "if": {"properties": {"terminal_status": {"const": "completed"}}},
            "then": {
                "properties": {
                    "action_outcome": {"const": "succeeded"},
                    "result_document": {
                        "allOf": [
                            {"$ref": "#/$defs/adapter_result"},
                            {"properties": {"outcome": {"const": "succeeded"}}},
                        ]
                    },
                    "adapter_call_count": {"const": 1},
                    "adapter_call_count_status": {"const": "exactly_one"},
                }
            },
        },
        {
            "if": {"properties": {"terminal_status": {"const": "failed_known"}}},
            "then": {
                "properties": {
                    "action_outcome": {"const": "failed"},
                    "result_document": {
                        "allOf": [
                            {"$ref": "#/$defs/adapter_result"},
                            {"properties": {"outcome": {"const": "failed"}}},
                        ]
                    },
                    "adapter_call_count": {"const": 1},
                    "adapter_call_count_status": {"const": "exactly_one"},
                }
            },
        },
        {
            "if": {
                "properties": {
                    "terminal_status": {"const": "predispatch_aborted"}
                }
            },
            "then": {
                "properties": {
                    "action_outcome": {"const": "failed"},
                    "evidence_status": {"const": "unknown"},
                    "cleanup_status": {"const": "unknown"},
                    "restoration_status": {"const": "unknown"},
                    "result_document": {"$ref": "#/$defs/quarantine_result"},
                    "charged_resources": {
                        "properties": {
                            field: {"const": 0} for field in RESOURCE_FIELDS
                        }
                    },
                    "adapter_call_count": {"const": 0},
                    "adapter_call_count_status": {"const": "exactly_zero"},
                }
            },
        },
        {
            "if": {
                "properties": {
                    "terminal_status": {"const": "indeterminate_quarantined"}
                }
            },
            "then": {
                "properties": {
                    "action_outcome": {"const": "indeterminate"},
                    "evidence_status": {"const": "unknown"},
                    "cleanup_status": {"const": "unknown"},
                    "restoration_status": {"const": "unknown"},
                    "result_document": {"$ref": "#/$defs/quarantine_result"},
                },
                "oneOf": [
                    {
                        "properties": {
                            "adapter_call_count": {"const": 1},
                            "adapter_call_count_status": {"const": "exactly_one"},
                        }
                    },
                    {
                        "properties": {
                            "adapter_call_count": {"type": "null"},
                            "adapter_call_count_status": {
                                "const": "unknown_zero_or_one"
                            },
                        }
                    },
                    {
                        "properties": {
                            "adapter_call_count": {"const": 0},
                            "adapter_call_count_status": {
                                "const": "exactly_zero"
                            },
                        }
                    },
                ],
            },
        },
    ]
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://sunderkey.dev/schemas/authenticated-action-execution-v1.schema.json",
        "title": "SUNDERKEY Authenticated Action Execution v1",
        "$defs": {
            "admission_authorization": admission_authorization,
            "admission_receipt": receipt,
            "adapter": adapter,
            "adapter_result": adapter_result,
            "authority_checks": checks,
            "authority_state": state,
            "authorization": authorization,
            "effects": effects,
            "quarantine_result": quarantine_result,
            "resources": resources,
            "positive_resources": positive_resources,
            "strict_object": strict_object,
            "strict_value": strict_value,
        },
        "oneOf": [request, claim, terminal],
    }


def main() -> None:
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(
        json.dumps(build_schema(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()

"""Build closed schemas for typed action resolution and admission records."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIRECTORY = ROOT / "registry/schemas"

COMMON = ("schema_version", "kind", "effects")
EFFECT_FIELDS = (
    "authorization_effect",
    "dispatch_performed",
    "model_call_performed",
    "network_call_performed",
    "qualification_effect",
    "target_action_performed",
    "tool_effect",
)
AUTHORIZATION_FIELDS = (
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
PARAMETER_CONTRACT_FIELDS = ("name", "required", "value_type")
CATALOG_ENTRY_FIELDS = (
    "action_type",
    "executor_supported",
    "maximum_action_tier",
    "parameter_contract",
    "parameter_contract_sha256",
    "r4_executor_supported",
    "supported_environments",
    "tool_artifact_ref",
    "tool_artifact_sha256",
    "tool_exact_version",
)

RESOLUTION_RECORD_FIELDS = {
    "executable_action_catalog": COMMON
    + (
        "catalog_id",
        "catalog_sha256",
        "catalog_name",
        "catalog_version",
        "registry_sha256",
        "entries",
    ),
    "action_parameter_set": COMMON
    + (
        "parameter_set_id",
        "parameter_set_sha256",
        "catalog_id",
        "catalog_sha256",
        "catalog_version",
        "action_type",
        "parameter_contract_sha256",
        "parameters",
    ),
    "target_action_descriptor": COMMON
    + (
        "descriptor_id",
        "descriptor_sha256",
        "tenant_id",
        "mission_id",
        "target_scope_sha256",
        "authority_snapshot_sha256",
        "target_id",
        "target_sha256",
        "environment",
    ),
    "action_proposal_resolution": COMMON
    + (
        "resolution_id",
        "resolution_sha256",
        "tenant_id",
        "mission_id",
        "plan_id",
        "proposal_work_id",
        "proposal_product_id",
        "proposal_product_sha256",
        "proposal_producer_profile_id",
        "review_snapshot_id",
        "review_snapshot_sha256",
        "review_closure_id",
        "review_closure_sha256",
        "catalog_id",
        "catalog_sha256",
        "catalog_version",
        "parameter_set_id",
        "parameter_set_sha256",
        "target_descriptor_id",
        "target_descriptor_sha256",
        "target_scope_sha256",
        "target_id",
        "target_sha256",
        "target_authority_sha256",
        "target_environment",
        "action_type",
        "action_tier",
        "action_sha256",
        "idempotency_key_sha256",
        "tool_artifact_ref",
        "tool_artifact_sha256",
        "tool_exact_version",
        "resolver_profile_id",
        "resolver_subject",
        "resolved_at",
        "resolution_status",
    ),
}

ADMISSION_RECORD_FIELDS = {
    "action_authorization_quorum": COMMON
    + (
        "quorum_id",
        "quorum_sha256",
        "resolution_id",
        "resolution_sha256",
        "tenant_id",
        "mission_id",
        "scope_sha256",
        "target_sha256",
        "action_sha256",
        "action_tier",
        "approvals",
        "approved_at",
        "expires_at",
        "quorum_status",
    ),
    "authenticated_action_admission_receipt": COMMON
    + (
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
    ),
    "action_admission_revocation": COMMON
    + (
        "revocation_id",
        "revocation_sha256",
        "receipt_id",
        "receipt_sha256",
        "resolution_id",
        "resolution_sha256",
        "tenant_id",
        "mission_id",
        "scope_sha256",
        "target_sha256",
        "action_sha256",
        "action_tier",
        "reason_code",
        "control_authorization",
        "revoked_at",
        "identity_assurance",
    ),
}


def _closed(fields: tuple[str, ...]) -> dict[str, Any]:
    return {
        "type": "object",
        "required": list(fields),
        "properties": {field: {"type": "string"} for field in fields},
        "additionalProperties": False,
    }


IDENTIFIER = {
    "type": "string",
    "pattern": "^[A-Za-z0-9][A-Za-z0-9._:/-]{2,255}$",
}
SHA256 = {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}
VERSION = {
    "type": "string",
    "pattern": (
        "^(?!(?:[Aa][Uu][Tt][Oo]|[Cc][Uu][Rr][Rr][Ee][Nn][Tt]|"
        "[Dd][Ee][Ff][Aa][Uu][Ll][Tt]|[Ll][Aa][Tt][Ee][Ss][Tt]|"
        "[Ss][Tt][Aa][Bb][Ll][Ee])$)"
        "(?=.*[0-9])[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$"
    ),
}
TIMESTAMP = {
    "type": "string",
    "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$",
}
TIER = {"enum": ["R0", "R1", "R2", "R3", "R4"]}
ENVIRONMENT = {"enum": ["sandbox", "replica", "live"]}
ASCII_TEXT = {
    "type": "string",
    "minLength": 1,
    "maxLength": 16384,
    "pattern": "^[\\x20-\\x7E]*$",
}


def _definitions() -> dict[str, Any]:
    parameter_contract = _closed(PARAMETER_CONTRACT_FIELDS)
    parameter_contract["properties"]["name"] = IDENTIFIER
    parameter_contract["properties"]["required"] = {"type": "boolean"}
    parameter_contract["properties"]["value_type"] = {
        "enum": [
            "string",
            "identifier",
            "sha256",
            "integer",
            "boolean",
            "string_array",
        ]
    }
    entry = _closed(CATALOG_ENTRY_FIELDS)
    entry["properties"]["action_type"] = IDENTIFIER
    entry["properties"]["executor_supported"] = {"type": "boolean"}
    entry["properties"]["maximum_action_tier"] = TIER
    entry["properties"]["r4_executor_supported"] = {"type": "boolean"}
    entry["properties"]["parameter_contract"] = {
        "type": "array",
        "maxItems": 128,
        "uniqueItems": True,
        "items": {"$ref": "#/$defs/parameter_contract"},
    }
    entry["properties"]["parameter_contract_sha256"] = SHA256
    entry["properties"]["supported_environments"] = {
        "type": "array",
        "minItems": 1,
        "maxItems": 3,
        "uniqueItems": True,
        "items": ENVIRONMENT,
    }
    entry["properties"]["tool_artifact_ref"] = IDENTIFIER
    entry["properties"]["tool_artifact_sha256"] = SHA256
    entry["properties"]["tool_exact_version"] = VERSION
    authorization = _closed(AUTHORIZATION_FIELDS)
    authorization["properties"].update(
        {
            "role": {
                "enum": [
                    "typed_resolver",
                    "mission_owner",
                    "independent_control",
                    "admission_control",
                ]
            },
            "authorized_tier": TIER,
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
        authorization["properties"][field] = IDENTIFIER
    for field in (
        "assertion_sha256",
        "assertion_key_sha256",
        "trust_policy_sha256",
        "scope_grant_sha256",
        "operation_intent_sha256",
        "canonical_replay_key_sha256",
        "scope_sha256",
        "target_sha256",
        "action_sha256",
        "resolution_sha256",
    ):
        authorization["properties"][field] = SHA256
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
    return {
        "effects": effects,
        "parameter_contract": parameter_contract,
        "catalog_entry": entry,
        "authorization": authorization,
    }


def _variant(kind: str, fields: tuple[str, ...]) -> dict[str, Any]:
    variant = _closed(fields)
    properties = variant["properties"]
    properties["schema_version"] = {"const": 1}
    properties["kind"] = {"const": kind}
    properties["effects"] = {"$ref": "#/$defs/effects"}
    id_fields = {
        "catalog_id",
        "parameter_set_id",
        "descriptor_id",
        "resolution_id",
        "quorum_id",
        "receipt_id",
        "revocation_id",
        "tenant_id",
        "mission_id",
        "plan_id",
        "proposal_work_id",
        "proposal_product_id",
        "proposal_producer_profile_id",
        "review_snapshot_id",
        "review_closure_id",
        "target_descriptor_id",
        "target_id",
        "action_type",
        "tool_artifact_ref",
        "resolver_profile_id",
        "resolver_subject",
        "request_id",
        "decision_id",
        "reason_code",
        "catalog_name",
    }
    sha_fields = {field for field in fields if field.endswith("_sha256")}
    for field in id_fields.intersection(fields):
        properties[field] = IDENTIFIER
    for field in sha_fields:
        properties[field] = SHA256
    for field in fields:
        if field.endswith("_at"):
            properties[field] = TIMESTAMP
    for field in ("catalog_version", "tool_exact_version"):
        if field in fields:
            properties[field] = VERSION
    if "action_tier" in fields:
        properties["action_tier"] = TIER
    if kind == "executable_action_catalog":
        properties["entries"] = {
            "type": "array",
            "minItems": 1,
            "maxItems": 4096,
            "uniqueItems": True,
            "items": {"$ref": "#/$defs/catalog_entry"},
        }
    elif kind == "action_parameter_set":
        properties["parameters"] = {
            "type": "object",
            "maxProperties": 128,
            "propertyNames": IDENTIFIER,
            "additionalProperties": {
                "oneOf": [
                    {"type": "boolean"},
                    {
                        "type": "integer",
                        "minimum": 0,
                        "maximum": 2**63 - 1,
                    },
                    ASCII_TEXT,
                    {
                        "type": "array",
                        "maxItems": 128,
                        "uniqueItems": True,
                        "items": ASCII_TEXT,
                    },
                ]
            },
        }
    elif kind == "target_action_descriptor":
        properties["environment"] = ENVIRONMENT
    elif kind == "action_proposal_resolution":
        properties["target_environment"] = ENVIRONMENT
        properties["resolution_status"] = {
            "const": "typed_resolved_pending_authorization"
        }
    elif kind == "action_authorization_quorum":
        properties["approvals"] = {
            "type": "array",
            "minItems": 1,
            "maxItems": 2,
            "uniqueItems": True,
            "items": {"$ref": "#/$defs/authorization"},
        }
        properties["quorum_status"] = {
            "const": "approved_for_contract_admission"
        }
    elif kind == "authenticated_action_admission_receipt":
        properties["admission_authorization"] = {"$ref": "#/$defs/authorization"}
        properties["identity_assurance"] = {
            "const": "mission_store_principal_assertion"
        }
        properties["status"] = {"const": "admitted_contract_only"}
    elif kind == "action_admission_revocation":
        properties["control_authorization"] = {"$ref": "#/$defs/authorization"}
        properties["identity_assurance"] = {
            "const": "mission_store_principal_assertion"
        }
    return variant


def executable_action_resolution_schema() -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://sunderkey.dev/schemas/executable-action-resolution-v1.schema.json",
        "title": "SUNDERKEY Executable Action Resolution v1",
        "$defs": _definitions(),
        "oneOf": [
            _variant(kind, fields) for kind, fields in RESOLUTION_RECORD_FIELDS.items()
        ],
    }


def authenticated_action_admission_schema() -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://sunderkey.dev/schemas/authenticated-action-admission-v1.schema.json",
        "title": "SUNDERKEY Authenticated Action Admission v1",
        "$defs": _definitions(),
        "oneOf": [
            _variant(kind, fields) for kind, fields in ADMISSION_RECORD_FIELDS.items()
        ],
    }


def main() -> None:
    SCHEMA_DIRECTORY.mkdir(parents=True, exist_ok=True)
    documents = {
        "executable-action-resolution-v1.schema.json": executable_action_resolution_schema(),
        "authenticated-action-admission-v1.schema.json": authenticated_action_admission_schema(),
    }
    for name, document in documents.items():
        (SCHEMA_DIRECTORY / name).write_text(
            json.dumps(document, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )


if __name__ == "__main__":
    main()

"""Build closed top-level schemas for portable expert review records."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIRECTORY = ROOT / "registry" / "schemas"

COMMON = ("schema_version", "kind", "effects")
RECORD_FIELDS = {
    "expert_review_snapshot": COMMON
    + (
        "snapshot_id",
        "snapshot_sha256",
        "tenant_id",
        "mission_id",
        "plan_id",
        "workspace_id",
        "workspace_sha256",
        "workspace_schema_version",
        "workspace_revision",
        "workspace_status",
        "runtime_catalog_id",
        "runtime_catalog_version",
        "runtime_catalog_sha256",
        "registry_sha256",
        "target_scope_sha256",
        "authority_snapshot_sha256",
        "evidence_snapshot_sha256",
        "event_count",
        "event_head_sha256",
        "event_head_occurred_at",
        "products",
        "review_slots",
        "review_policy",
    ),
    "expert_review_submission": COMMON
    + (
        "submission_id",
        "submission_sha256",
        "snapshot_id",
        "snapshot_sha256",
        "work_id",
        "product_id",
        "product_sha256",
        "reviewer_profile_id",
        "reviewer_role",
        "decision",
        "reason_code",
        "evidence_reference_sha256s",
        "affected_work_ids",
        "required_correction_ids",
        "rationale",
    ),
    "authenticated_expert_review_receipt": COMMON
    + (
        "receipt_id",
        "receipt_sha256",
        "submission_id",
        "submission_sha256",
        "submission",
        "reviewer_subject",
        "assertion_issuer",
        "assertion_id",
        "assertion_sha256",
        "assertion_key_sha256",
        "trust_policy_sha256",
        "scope_grant_sha256",
        "operation_intent_sha256",
        "canonical_replay_key_sha256",
        "recorded_at",
        "identity_assurance",
    ),
    "expert_review_closure_request": COMMON
    + (
        "closure_request_id",
        "closure_request_sha256",
        "snapshot_id",
        "snapshot_sha256",
        "review_receipts",
        "expected_disposition",
        "closer_profile_id",
        "requested_at",
    ),
    "expert_review_closure_certificate": COMMON
    + (
        "closure_id",
        "closure_sha256",
        "closure_request_id",
        "closure_request_sha256",
        "snapshot_id",
        "snapshot_sha256",
        "review_receipt_ids",
        "review_set_sha256",
        "disposition",
        "rejected_work_ids",
        "rework_work_ids",
        "required_correction_ids",
        "closer_subject",
        "closer_profile_id",
        "assertion_issuer",
        "assertion_id",
        "assertion_sha256",
        "assertion_key_sha256",
        "trust_policy_sha256",
        "scope_grant_sha256",
        "operation_intent_sha256",
        "canonical_replay_key_sha256",
        "closed_at",
        "identity_assurance",
    ),
    "expert_review_closure_revocation": COMMON
    + (
        "revocation_id",
        "revocation_sha256",
        "closure_id",
        "closure_sha256",
        "reason_code",
        "control_subject",
        "control_profile_id",
        "assertion_issuer",
        "assertion_id",
        "assertion_sha256",
        "operation_intent_sha256",
        "canonical_replay_key_sha256",
        "revoked_at",
        "identity_assurance",
    ),
}
APPLICATION_FIELDS = COMMON + (
    "application_id",
    "application_sha256",
    "mission_store_id",
    "workspace_id",
    "snapshot_id",
    "snapshot_sha256",
    "closure_id",
    "closure_sha256",
    "disposition",
    "workspace_revision_before",
    "workspace_revision_after",
    "event_head_before_sha256",
    "applied_at",
)
AUTHENTICATED_REGISTRATION_FIELDS = COMMON + (
    "registration_id",
    "registration_sha256",
    "snapshot_id",
    "snapshot_sha256",
    "mission_id",
    "tenant_id",
    "active_plan_id",
    "active_plan_sha256",
    "active_plan_version",
    "mission_revision",
    "workspace_id",
    "workspace_sha256",
    "workspace_schema_version",
    "workspace_revision",
    "workspace_event_count",
    "workspace_event_head_sha256",
    "runtime_catalog_id",
    "runtime_catalog_version",
    "runtime_catalog_sha256",
    "registry_sha256",
    "target_scope_sha256",
    "authority_snapshot_sha256",
    "evidence_snapshot_sha256",
    "registrar_profile_id",
    "registrar_subject",
    "assertion_issuer",
    "assertion_id",
    "assertion_sha256",
    "assertion_key_sha256",
    "trust_policy_sha256",
    "scope_grant_sha256",
    "operation_intent_sha256",
    "canonical_replay_key_sha256",
    "domain_request_sha256",
    "registered_at",
)

NESTED_FIELDS = {
    "effects": (
        "authorization_effect",
        "model_call_performed",
        "network_call_performed",
        "qualification_effect",
        "target_action_performed",
        "tool_effect",
    ),
    "product": (
        "work_id",
        "producer_profile_id",
        "command_id",
        "product_id",
        "product_sha256",
        "product_type",
        "envelope_id",
        "envelope_sha256",
        "attempt_number",
        "fencing_token",
        "review_required",
        "dependency_product_ids",
        "lineage_product_ids",
        "disagreement_sha256s",
    ),
    "review_slot": (
        "work_id",
        "product_id",
        "product_sha256",
        "reviewer_profile_id",
        "reviewer_role",
        "profile_sha256",
        "policy_template_id",
        "policy_template_sha256",
        "registry_sha256",
        "producer_profile_ids_excluded",
    ),
    "review_policy": (
        "all_slots_mandatory",
        "decision_precedence",
        "policy_id",
        "producer_and_lineage_excluded",
        "schema_version",
        "policy_sha256",
    ),
    "receipt_binding": ("receipt_id", "receipt_sha256"),
}

IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/-]{2,255}$"
PROFILE_PATTERN = r"^AOE-(?:G[A-E]-D[0-9]{2}-(?:S[0-9]{2}|CMD)|HQ-[0-9]{2})$"
SHA256_PATTERN = r"^sha256:[0-9a-f]{64}$"
ASCII_TEXT_PATTERN = r"^[\t\n\r\x20-\x7e]+$"
MAX_SIGNED_INTEGER = 2**63 - 1
MAX_TEXT_ITEMS = 512
MAX_REVIEW_SLOTS = 32_768
MAX_RATIONALE_CHARACTERS = 16_384
RECORD_ID_PATTERNS = {
    "expert_review_snapshot": r"^ERS-[0-9A-F]{32}$",
    "expert_review_submission": r"^ERSU-[0-9A-F]{32}$",
    "authenticated_expert_review_receipt": r"^ERR-[0-9A-F]{32}$",
    "expert_review_closure_request": r"^ECRQ-[0-9A-F]{32}$",
    "expert_review_closure_certificate": r"^ERC-[0-9A-F]{32}$",
    "expert_review_closure_revocation": r"^ECRV-[0-9A-F]{32}$",
    "expert_workspace_closure_application": r"^ECAP-[0-9A-F]{32}$",
}
RECORD_ID_FIELDS = {
    "expert_review_snapshot": "snapshot_id",
    "expert_review_submission": "submission_id",
    "authenticated_expert_review_receipt": "receipt_id",
    "expert_review_closure_request": "closure_request_id",
    "expert_review_closure_certificate": "closure_id",
    "expert_review_closure_revocation": "revocation_id",
    "expert_workspace_closure_application": "application_id",
}


def _identifier() -> dict[str, Any]:
    return {"type": "string", "pattern": IDENTIFIER_PATTERN}


def _profile() -> dict[str, Any]:
    return {"type": "string", "pattern": PROFILE_PATTERN}


def _sha256() -> dict[str, Any]:
    return {"type": "string", "pattern": SHA256_PATTERN}


def _integer(minimum: int = 0) -> dict[str, Any]:
    return {"type": "integer", "minimum": minimum, "maximum": MAX_SIGNED_INTEGER}


def _identifier_array(*, maximum: int = MAX_TEXT_ITEMS, minimum: int = 0) -> dict[str, Any]:
    return {
        "type": "array",
        "items": _identifier(),
        "minItems": minimum,
        "maxItems": maximum,
        "uniqueItems": True,
    }


def _sha256_array() -> dict[str, Any]:
    return {
        "type": "array",
        "items": _sha256(),
        "maxItems": MAX_TEXT_ITEMS,
        "uniqueItems": True,
    }


def _field_schema(field: str) -> dict[str, Any]:
    if field.endswith("_sha256"):
        return _sha256()
    if field.endswith("_sha256s"):
        return _sha256_array()
    if field in {
        "reviewer_profile_id",
        "closer_profile_id",
        "control_profile_id",
        "producer_profile_id",
    }:
        return _profile()
    if field in {"producer_profile_ids_excluded"}:
        return {
            "type": "array",
            "items": _profile(),
            "minItems": 1,
            "maxItems": MAX_TEXT_ITEMS,
            "uniqueItems": True,
        }
    if field in {
        "workspace_schema_version",
        "workspace_revision",
        "event_count",
        "event_head_occurred_at",
        "recorded_at",
        "requested_at",
        "closed_at",
        "revoked_at",
        "workspace_revision_before",
        "workspace_revision_after",
        "applied_at",
    }:
        return _integer(1 if field in {"workspace_schema_version", "event_count"} else 0)
    if field in {"attempt_number", "fencing_token"}:
        return _integer(1)
    if field in {"all_slots_mandatory", "producer_and_lineage_excluded"}:
        return {"const": True}
    if field == "review_required":
        return {"type": "boolean"}
    if field == "reviewer_role":
        return {
            "enum": [
                "technical_evaluator",
                "independent_control",
                "independent_assurance",
            ]
        }
    if field == "decision":
        return {"enum": ["accepted", "rejected", "rework_required"]}
    if field in {"disposition", "expected_disposition"}:
        return {"enum": ["accepted", "rejected", "rework_required"]}
    if field == "workspace_status":
        return {"const": "products_complete_pending_review"}
    if field == "identity_assurance":
        return {"const": "mission_store_principal_assertion"}
    if field == "rationale":
        return {
            "type": "string",
            "minLength": 1,
            "maxLength": MAX_RATIONALE_CHARACTERS,
            "pattern": ASCII_TEXT_PATTERN,
        }
    if field in {
        "dependency_product_ids",
        "lineage_product_ids",
        "affected_work_ids",
        "required_correction_ids",
        "rejected_work_ids",
        "rework_work_ids",
    }:
        return _identifier_array()
    if field == "review_receipt_ids":
        return _identifier_array(maximum=MAX_REVIEW_SLOTS, minimum=1)
    if field == "decision_precedence":
        return {"const": ["rejected", "rework_required", "accepted"]}
    if field == "schema_version":
        return {"const": 1}
    return _identifier()


def _closed_fields(
    fields: tuple[str, ...],
    *,
    properties: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "type": "object",
        "required": list(fields),
        "properties": properties or {field: _field_schema(field) for field in fields},
        "additionalProperties": False,
    }


def _definitions() -> dict[str, Any]:
    effects = {
        "authorization_effect": {"const": "none"},
        "model_call_performed": {"const": False},
        "network_call_performed": {"const": False},
        "qualification_effect": {"const": "none"},
        "target_action_performed": {"const": False},
        "tool_effect": {"const": "none"},
    }
    definitions = {name: _closed_fields(fields) for name, fields in NESTED_FIELDS.items()}
    definitions["effects"] = _closed_fields(NESTED_FIELDS["effects"], properties=effects)
    definitions["review_policy"] = _closed_fields(
        NESTED_FIELDS["review_policy"],
        properties={field: _field_schema(field) for field in NESTED_FIELDS["review_policy"]}
        | {
            "policy_id": {"const": "sunderkey.expert-review-policy.v1"},
        },
    )
    definitions["submission"] = _closed_variant(
        "expert_review_submission", RECORD_FIELDS["expert_review_submission"]
    )
    return definitions


def _closed_variant(kind: str, fields: tuple[str, ...]) -> dict[str, Any]:
    properties: dict[str, Any] = {field: _field_schema(field) for field in fields}
    properties["schema_version"] = {"const": 1}
    properties["kind"] = {"const": kind}
    properties[RECORD_ID_FIELDS[kind]] = {
        "type": "string",
        "pattern": RECORD_ID_PATTERNS[kind],
    }
    properties["effects"] = {"$ref": "#/$defs/effects"}
    if kind == "expert_review_snapshot":
        properties["products"] = {
            "type": "array",
            "items": {"$ref": "#/$defs/product"},
            "minItems": 1,
            "maxItems": MAX_TEXT_ITEMS,
        }
        properties["review_slots"] = {
            "type": "array",
            "items": {"$ref": "#/$defs/review_slot"},
            "minItems": 1,
            "maxItems": MAX_REVIEW_SLOTS,
        }
        properties["review_policy"] = {"$ref": "#/$defs/review_policy"}
    elif kind == "authenticated_expert_review_receipt":
        properties["submission"] = {"$ref": "#/$defs/submission"}
    elif kind == "expert_review_closure_request":
        properties["review_receipts"] = {
            "type": "array",
            "items": {"$ref": "#/$defs/receipt_binding"},
            "minItems": 1,
            "maxItems": MAX_REVIEW_SLOTS,
        }
    return {
        "type": "object",
        "required": list(fields),
        "properties": properties,
        "additionalProperties": False,
    }


def expert_review_record_schema() -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://sunderkey.example/schemas/expert-review-record-v1.schema.json",
        "title": "SUNDERKEY Expert Review Record v1",
        "$defs": _definitions(),
        "oneOf": [_closed_variant(kind, fields) for kind, fields in RECORD_FIELDS.items()],
    }


def expert_workspace_closure_application_schema() -> dict[str, Any]:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": (
            "https://sunderkey.example/schemas/expert-workspace-closure-application-v1.schema.json"
        ),
        "title": "SUNDERKEY Expert Workspace Closure Application v1",
        "$defs": {"effects": _definitions()["effects"]},
        **_closed_variant("expert_workspace_closure_application", APPLICATION_FIELDS),
    }


def authenticated_expert_review_registration_schema() -> dict[str, Any]:
    properties = {field: _field_schema(field) for field in AUTHENTICATED_REGISTRATION_FIELDS}
    properties.update(
        {
            "schema_version": {"const": 1},
            "kind": {"const": "authenticated_expert_review_registration"},
            "registration_id": {
                "type": "string",
                "pattern": r"^ERRG-[0-9A-F]{32}$",
            },
            "active_plan_version": _integer(1),
            "mission_revision": _integer(),
            "workspace_schema_version": _integer(1),
            "workspace_revision": _integer(),
            "workspace_event_count": _integer(1),
            "registered_at": _integer(),
            "registrar_profile_id": _profile(),
            "effects": {"$ref": "#/$defs/effects"},
        }
    )
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": (
            "https://sunderkey.example/schemas/"
            "authenticated-expert-review-registration-v1.schema.json"
        ),
        "title": "SUNDERKEY Authenticated Expert Review Registration v1",
        "$defs": {"effects": _definitions()["effects"]},
        **_closed_fields(AUTHENTICATED_REGISTRATION_FIELDS, properties=properties),
    }


def main() -> None:
    SCHEMA_DIRECTORY.mkdir(parents=True, exist_ok=True)
    documents = {
        "expert-review-record-v1.schema.json": expert_review_record_schema(),
        "expert-workspace-closure-application-v1.schema.json": (
            expert_workspace_closure_application_schema()
        ),
        "authenticated-expert-review-registration-v1.schema.json": (
            authenticated_expert_review_registration_schema()
        ),
    }
    for name, document in documents.items():
        (SCHEMA_DIRECTORY / name).write_text(
            json.dumps(document, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )


if __name__ == "__main__":
    main()

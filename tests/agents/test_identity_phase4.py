"""Tests for authenticated principal credentials."""

from __future__ import annotations

import base64
import hashlib
import json
import stat
import tempfile
import unittest
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import sunderkey.identity as identity_module
from sunderkey.errors import PrincipalAuthenticationError
from sunderkey.identity import (
    PrincipalAssertion,
    PrincipalOperation,
    PrincipalTrustPolicy,
    ScopeGrant,
    TrustKeyState,
    TrustKeyUse,
    _strict_ed25519_public_key,
    _verify_ed25519,
    compute_operation_intent_hash,
    load_principal_assertion,
    load_scope_grant,
    load_trust_policy,
    verify_principal_assertion,
    verify_scope_grant,
    verify_trust_policy,
)

NOW = datetime(2026, 7, 30, 10, 5, tzinfo=UTC)
AUDIENCE = "sunderkey-runtime"
STORE_ID = "STR-0123456789ABCDEF0123456789ABCDEF"
OTHER_STORE_ID = "STR-FEDCBA9876543210FEDCBA9876543210"
MISSION_ID = "MISSION-PHASE4"
PROFILE_ID = "AOE-HQ-12"
OTHER_PROFILE_ID = "AOE-GA-D01-CMD"
SUBJECT = "operator:alice"
OTHER_SUBJECT = "operator:mallory"
ROOT_KEY_ID = "ROOT-2026"
ASSERTION_KEY_ID = "ASSERTION-2026"
SCOPE_KEY_ID = "SCOPE-2026"
POLICY_ID = "POLICY-PHASE4"
GRANT_ID = "SGR-0123456789ABCDEF0123456789ABCDEF"
OTHER_GRANT_ID = "SGR-FEDCBA9876543210FEDCBA9876543210"
ASSERTION_ID = "PAS-0123456789ABCDEF0123456789ABCDEF"
OTHER_ASSERTION_ID = "PAS-FEDCBA9876543210FEDCBA9876543210"
ZERO_SIGNATURE = base64.urlsafe_b64encode(bytes(64)).rstrip(b"=").decode("ascii")
IDENTITY_POINT = b"\x01" + bytes(31)
IDENTITY_SIGNATURE = (
    base64.urlsafe_b64encode(IDENTITY_POINT + bytes(32))
    .rstrip(b"=")
    .decode("ascii")
)
ED25519_SUBGROUP_ORDER = (
    2**252 + 27742317777372353535851937790883648493
)
MISSION_CONTEXT_HASH = "sha256:" + "1" * 64
SCOPE_DOCUMENT_HASH = "sha256:" + "2" * 64
CONSTRAINTS_HASH = "sha256:" + "3" * 64
IDEMPOTENCY_KEY_HASH = "sha256:" + "4" * 64
EVENT_BATCH_HASH = "sha256:" + "5" * 64
SCOPE_REFERENCE = "SCOPE-PHASE4"


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def public_bytes(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def operation_intent(
    operation: PrincipalOperation,
) -> dict[str, Any]:
    def replacement_intent(
        role: str,
        *,
        work_item_id: str | None,
        command: bool = False,
    ) -> dict[str, Any]:
        value: dict[str, Any] = {
            "authority_intent_sha256": "sha256:" + "6" * 64,
            "mission_id": MISSION_ID,
            "principal_profile_id": OTHER_PROFILE_ID if command else PROFILE_ID,
            "prior_plan_id": "CLP-" + "A" * 24,
            "prior_plan_sha256": "sha256:" + "7" * 64,
            "replacement_plan_id": "CLP-" + "B" * 24,
            "replacement_plan_sha256": "sha256:" + "8" * 64,
            "role": role,
            "selection_sha256": "sha256:" + "9" * 64,
            "work_item_id": work_item_id,
        }
        if command:
            value["command_authority_binding_sha256"] = "sha256:" + "a" * 64
        return value

    intents: dict[PrincipalOperation, dict[str, Any]] = {
        PrincipalOperation.MISSION_CREATE: {
            "mission_context_sha256": MISSION_CONTEXT_HASH,
            "mission_id": MISSION_ID,
            "principal_profile_id": PROFILE_ID,
        },
        PrincipalOperation.COLLABORATION_ACTIVATE: {
            "mission_id": MISSION_ID,
            "plan_content_sha256": MISSION_CONTEXT_HASH,
            "plan_id": "CLP-" + "A" * 24,
            "principal_profile_id": PROFILE_ID,
        },
        PrincipalOperation.MODEL_EXECUTE: {
            "execution_admission_core_sha256": MISSION_CONTEXT_HASH,
            "mission_id": MISSION_ID,
            "principal_profile_id": PROFILE_ID,
        },
        PrincipalOperation.ACTION_RESOLVE: {
            "action_intent_sha256": MISSION_CONTEXT_HASH,
            "idempotency_key_sha256": IDEMPOTENCY_KEY_HASH,
            "mission_id": MISSION_ID,
            "principal_profile_id": PROFILE_ID,
            "role": "typed_resolver",
        },
        PrincipalOperation.ACTION_QUORUM_AUTHORIZE: {
            "action_intent_sha256": MISSION_CONTEXT_HASH,
            "idempotency_key_sha256": IDEMPOTENCY_KEY_HASH,
            "mission_id": MISSION_ID,
            "principal_profile_id": PROFILE_ID,
            "role": "mission_owner",
        },
        PrincipalOperation.ACTION_ADMIT: {
            "action_intent_sha256": MISSION_CONTEXT_HASH,
            "idempotency_key_sha256": IDEMPOTENCY_KEY_HASH,
            "mission_id": MISSION_ID,
            "principal_profile_id": PROFILE_ID,
            "role": "admission_control",
        },
        PrincipalOperation.ACTION_EXECUTE: {
            "action_intent_sha256": MISSION_CONTEXT_HASH,
            "idempotency_key_sha256": IDEMPOTENCY_KEY_HASH,
            "mission_id": MISSION_ID,
            "principal_profile_id": PROFILE_ID,
            "role": "admission_control",
        },
        PrincipalOperation.ACTION_EXECUTION_RECONCILE: {
            "action_intent_sha256": MISSION_CONTEXT_HASH,
            "idempotency_key_sha256": IDEMPOTENCY_KEY_HASH,
            "mission_id": MISSION_ID,
            "principal_profile_id": PROFILE_ID,
            "role": "independent_control",
        },
        PrincipalOperation.TARGET_HEALTH_GATE_RESUME: {
            "idempotency_key_sha256": IDEMPOTENCY_KEY_HASH,
            "mission_id": MISSION_ID,
            "principal_profile_id": PROFILE_ID,
            "recovery_intent_sha256": EVENT_BATCH_HASH,
            "role": "independent_control",
        },
        PrincipalOperation.ACTION_ADMISSION_REVOKE: {
            "action_intent_sha256": MISSION_CONTEXT_HASH,
            "idempotency_key_sha256": IDEMPOTENCY_KEY_HASH,
            "mission_id": MISSION_ID,
            "principal_profile_id": PROFILE_ID,
            "role": "independent_control",
        },
        PrincipalOperation.ACTION_AUTHORITY_PUBLISH: {
            "idempotency_key_sha256": IDEMPOTENCY_KEY_HASH,
            "mission_id": MISSION_ID,
            "principal_profile_id": PROFILE_ID,
            "publication_sha256": MISSION_CONTEXT_HASH,
        },
        PrincipalOperation.COLLABORATION_POLICY_OWNER_AUTHORIZE: {
            "mission_id": MISSION_ID,
            "policy_selection_sha256": MISSION_CONTEXT_HASH,
            "principal_profile_id": PROFILE_ID,
        },
        PrincipalOperation.COLLABORATION_POLICY_CONTROL_APPROVE: {
            "mission_id": MISSION_ID,
            "policy_selection_sha256": MISSION_CONTEXT_HASH,
            "principal_profile_id": PROFILE_ID,
        },
        PrincipalOperation.EXECUTION_CHANNEL_POLICY_OWNER_AUTHORIZE: {
            "channel_policy_selection_sha256": MISSION_CONTEXT_HASH,
            "mission_id": MISSION_ID,
            "principal_profile_id": PROFILE_ID,
        },
        PrincipalOperation.EXECUTION_CHANNEL_POLICY_CONTROL_APPROVE: {
            "channel_policy_selection_sha256": MISSION_CONTEXT_HASH,
            "mission_id": MISSION_ID,
            "principal_profile_id": PROFILE_ID,
        },
        PrincipalOperation.EXECUTION_TRANSFER_REQUEST_AUTHORIZE: {
            "mission_id": MISSION_ID,
            "principal_profile_id": PROFILE_ID,
            "request_selection_sha256": MISSION_CONTEXT_HASH,
        },
        PrincipalOperation.EXECUTION_TRANSFER_ACKNOWLEDGE: {
            "acknowledgement_selection_sha256": MISSION_CONTEXT_HASH,
            "mission_id": MISSION_ID,
            "principal_profile_id": PROFILE_ID,
            "request_id": "ETR-" + "A" * 32,
            "request_sha256": SCOPE_DOCUMENT_HASH,
        },
        PrincipalOperation.EXECUTION_TIMEOUT_RESOLVE: {
            "mission_id": MISSION_ID,
            "principal_profile_id": PROFILE_ID,
            "resolution_selection_sha256": MISSION_CONTEXT_HASH,
        },
        PrincipalOperation.EXECUTION_SESSION_ACTIVATE_AUTHORIZE: {
            "activation_selection_sha256": MISSION_CONTEXT_HASH,
            "mission_id": MISSION_ID,
            "principal_profile_id": PROFILE_ID,
        },
        PrincipalOperation.EXECUTION_SESSION_ACTIVATE_ACCEPT: {
            "activation_selection_sha256": MISSION_CONTEXT_HASH,
            "mission_id": MISSION_ID,
            "principal_profile_id": PROFILE_ID,
        },
        PrincipalOperation.EXECUTION_SESSION_REVOKE: {
            "mission_id": MISSION_ID,
            "principal_profile_id": PROFILE_ID,
            "revocation_selection_sha256": MISSION_CONTEXT_HASH,
        },
        PrincipalOperation.EXECUTOR_ACKNOWLEDGE: {
            "acknowledgement_selection_sha256": MISSION_CONTEXT_HASH,
            "dispatch_sha256": SCOPE_DOCUMENT_HASH,
            "mission_id": MISSION_ID,
            "principal_profile_id": PROFILE_ID,
        },
        PrincipalOperation.EXECUTOR_ACKNOWLEDGE_SAFETY: {
            "acknowledgement_selection_sha256": MISSION_CONTEXT_HASH,
            "dispatch_sha256": SCOPE_DOCUMENT_HASH,
            "mission_id": MISSION_ID,
            "principal_profile_id": PROFILE_ID,
        },
        PrincipalOperation.EVIDENCE_REPOSITORY_ACKNOWLEDGE: {
            "ingest_receipt_selection_sha256": MISSION_CONTEXT_HASH,
            "ingest_request_sha256": SCOPE_DOCUMENT_HASH,
            "lifecycle_policy_sha256": CONSTRAINTS_HASH,
            "mission_id": MISSION_ID,
            "principal_profile_id": PROFILE_ID,
        },
        PrincipalOperation.EXECUTOR_DISPATCH_AUTHORIZE: {
            "dispatch_selection_sha256": MISSION_CONTEXT_HASH,
            "mission_id": MISSION_ID,
            "principal_profile_id": PROFILE_ID,
        },
        PrincipalOperation.EXECUTOR_DISPATCH_SAFETY_AUTHORIZE: {
            "dispatch_selection_sha256": MISSION_CONTEXT_HASH,
            "mission_id": MISSION_ID,
            "principal_profile_id": PROFILE_ID,
        },
        PrincipalOperation.COLLABORATION_OWNERSHIP_CURRENT_OWNER_AUTHORIZE: {
            "entry_id": "OCE-" + "A" * 32,
            "entry_sha256": MISSION_CONTEXT_HASH,
            "mission_id": MISSION_ID,
            "preflight_id": "OTP-" + "A" * 32,
            "preflight_sha256": SCOPE_DOCUMENT_HASH,
            "principal_profile_id": PROFILE_ID,
        },
        PrincipalOperation.COLLABORATION_OWNERSHIP_PROPOSED_OWNER_ACCEPT: {
            "entry_id": "OCE-" + "A" * 32,
            "entry_sha256": MISSION_CONTEXT_HASH,
            "mission_id": MISSION_ID,
            "preflight_id": "OTP-" + "A" * 32,
            "preflight_sha256": SCOPE_DOCUMENT_HASH,
            "principal_profile_id": PROFILE_ID,
        },
        PrincipalOperation.COLLABORATION_OWNERSHIP_CONTROL_APPROVE: {
            "entry_id": "OCE-" + "A" * 32,
            "entry_sha256": MISSION_CONTEXT_HASH,
            "mission_id": MISSION_ID,
            "preflight_id": "OTP-" + "A" * 32,
            "preflight_sha256": SCOPE_DOCUMENT_HASH,
            "principal_profile_id": PROFILE_ID,
        },
        PrincipalOperation.COLLABORATION_OWNERSHIP_SECOND_AUTHORITY_APPROVE: {
            "entry_id": "OCE-" + "A" * 32,
            "entry_sha256": MISSION_CONTEXT_HASH,
            "mission_id": MISSION_ID,
            "preflight_id": "OPF-" + "A" * 32,
            "preflight_sha256": SCOPE_DOCUMENT_HASH,
            "principal_profile_id": PROFILE_ID,
        },
        PrincipalOperation.WORK_CLAIM: {
            "expected_generation": 0,
            "mission_id": MISSION_ID,
            "plan_content_sha256": MISSION_CONTEXT_HASH,
            "plan_id": "CLP-" + "A" * 24,
            "principal_profile_id": PROFILE_ID,
            "work_item_id": "WIT-READY-" + "A" * 16,
        },
        PrincipalOperation.WORK_RENEW: {
            "claim_generation": 1,
            "expected_lease_expires_at": (
                "2026-07-30T10:20:00Z"
            ),
            "mission_id": MISSION_ID,
            "plan_content_sha256": MISSION_CONTEXT_HASH,
            "plan_id": "CLP-" + "A" * 24,
            "previous_transition_id": "WLT-" + "A" * 32,
            "principal_profile_id": PROFILE_ID,
            "work_item_id": "WIT-READY-" + "A" * 16,
        },
        PrincipalOperation.WORK_RELEASE: {
            "claim_generation": 1,
            "expected_lease_expires_at": (
                "2026-07-30T10:20:00Z"
            ),
            "mission_id": MISSION_ID,
            "plan_content_sha256": MISSION_CONTEXT_HASH,
            "plan_id": "CLP-" + "A" * 24,
            "previous_transition_id": "WLT-" + "A" * 32,
            "principal_profile_id": PROFILE_ID,
            "reason": "Owner released the lease",
            "reason_code": "owner_release",
            "work_item_id": "WIT-READY-" + "A" * 16,
        },
        PrincipalOperation.WORK_COMPLETE: {
            "claim_generation": 1,
            "evidence_manifest_sha256": (
                "sha256:" + "6" * 64
            ),
            "expected_lease_expires_at": (
                "2026-07-30T10:20:00Z"
            ),
            "mission_id": MISSION_ID,
            "plan_content_sha256": MISSION_CONTEXT_HASH,
            "plan_id": "CLP-" + "A" * 24,
            "previous_transition_id": "WLT-" + "A" * 32,
            "principal_profile_id": PROFILE_ID,
            "result_id": "RES-PHASE4",
            "result_sha256": "sha256:" + "7" * 64,
            "work_item_id": "WIT-READY-" + "A" * 16,
        },
        PrincipalOperation.WORK_RECOVERY_REQUEST: {
            "expected_generation": 3,
            "expected_lease_expires_at": (
                "2026-07-30T10:20:00Z"
            ),
            "mission_id": MISSION_ID,
            "plan_content_sha256": MISSION_CONTEXT_HASH,
            "plan_id": "CLP-" + "A" * 24,
            "previous_transition_id": "WLT-" + "A" * 32,
            "principal_profile_id": PROFILE_ID,
            "reason": "Three attempts were exhausted",
            "reason_code": "attempts_exhausted",
            "remediation": "Apply the reviewed recovery procedure",
            "requested_attempts": 3,
            "work_item_id": "WIT-READY-" + "A" * 16,
        },
        PrincipalOperation.WORK_RECOVERY_APPROVE: {
            "additional_attempts": 3,
            "authority": "Independent Control",
            "constraints": ["same owner only"],
            "decision_owner": "independent-control",
            "mission_id": MISSION_ID,
            "owner_profile_id": PROFILE_ID,
            "plan_content_sha256": MISSION_CONTEXT_HASH,
            "plan_id": "CLP-" + "A" * 24,
            "principal_profile_id": OTHER_PROFILE_ID,
            "recovery_epoch": 1,
            "recovery_request_id": "WRQ-" + "A" * 32,
            "recovery_request_sha256": MISSION_CONTEXT_HASH,
            "work_item_id": "WIT-READY-" + "A" * 16,
        },
        PrincipalOperation.WORK_RECOVERY_DENY: {
            "additional_attempts": 3,
            "decision_owner": "independent-control",
            "mission_id": MISSION_ID,
            "owner_profile_id": PROFILE_ID,
            "plan_content_sha256": MISSION_CONTEXT_HASH,
            "plan_id": "CLP-" + "A" * 24,
            "principal_profile_id": OTHER_PROFILE_ID,
            "reason": "Recovery risk is not acceptable",
            "reason_code": "risk_unacceptable",
            "recovery_epoch": 1,
            "recovery_request_id": "WRQ-" + "A" * 32,
            "recovery_request_sha256": MISSION_CONTEXT_HASH,
            "risk": "Further work exceeds the reviewed boundary",
            "work_item_id": "WIT-READY-" + "A" * 16,
        },
        PrincipalOperation.WORK_CANCEL: {
            "affected_work_item_ids": [
                "WIT-READY-" + "A" * 16
            ],
            "cancellation_scope": "item_and_descendants",
            "decision_owner": "independent-control",
            "expected_generation": 1,
            "expected_lease_expires_at": (
                "2026-07-30T10:20:00Z"
            ),
            "mission_id": MISSION_ID,
            "owner_profile_id": PROFILE_ID,
            "plan_content_sha256": MISSION_CONTEXT_HASH,
            "plan_id": "CLP-" + "A" * 24,
            "previous_transition_id": "WLT-" + "A" * 32,
            "principal_profile_id": OTHER_PROFILE_ID,
            "reason": "The work package is no longer required",
            "reason_code": "scope_reduced",
            "risk": "Continuing exceeds the revised mission need",
            "work_item_id": "WIT-READY-" + "A" * 16,
        },
        PrincipalOperation.WORK_HANDOFF_AUTHORIZE: {
            "candidate_assertion_id": "PAS-" + "B" * 32,
            "candidate_issuer": "identity-provider",
            "candidate_profile_id": OTHER_PROFILE_ID,
            "candidate_profile_version": "1.0.0",
            "candidate_registry_status": "qualified",
            "expected_generation": 1,
            "expected_lease_expires_at": (
                "2026-07-30T10:20:00Z"
            ),
            "handoff_scope": "remaining_specialist_work",
            "mission_id": MISSION_ID,
            "owner_assertion_id": "PAS-" + "A" * 32,
            "owner_issuer": "identity-provider",
            "plan_content_sha256": MISSION_CONTEXT_HASH,
            "plan_id": "CLP-" + "A" * 24,
            "planned_owner_profile_id": PROFILE_ID,
            "previous_transition_id": "WLT-" + "A" * 32,
            "principal_profile_id": PROFILE_ID,
            "qualification_basis": (
                "assigned_qualified_same_command_v1"
            ),
            "qualification_command_id": "AOE-GA-D01",
            "reason": "Balance the assigned specialist workload",
            "reason_code": "load_balance",
            "work_item_id": "WIT-SPEC-" + "A" * 16,
            "work_item_kind": "specialist_analysis",
        },
        PrincipalOperation.WORK_HANDOFF_ACCEPT: {
            "candidate_assertion_id": "PAS-" + "B" * 32,
            "candidate_issuer": "identity-provider",
            "candidate_profile_id": OTHER_PROFILE_ID,
            "candidate_profile_version": "1.0.0",
            "candidate_registry_status": "qualified",
            "expected_generation": 1,
            "expected_lease_expires_at": (
                "2026-07-30T10:20:00Z"
            ),
            "handoff_scope": "remaining_specialist_work",
            "mission_id": MISSION_ID,
            "owner_assertion_id": "PAS-" + "A" * 32,
            "owner_issuer": "identity-provider",
            "plan_content_sha256": MISSION_CONTEXT_HASH,
            "plan_id": "CLP-" + "A" * 24,
            "planned_owner_profile_id": PROFILE_ID,
            "previous_transition_id": "WLT-" + "A" * 32,
            "principal_profile_id": OTHER_PROFILE_ID,
            "qualification_basis": (
                "assigned_qualified_same_command_v1"
            ),
            "qualification_command_id": "AOE-GA-D01",
            "reason": "Balance the assigned specialist workload",
            "reason_code": "load_balance",
            "work_item_id": "WIT-SPEC-" + "A" * 16,
            "work_item_kind": "specialist_analysis",
        },
        PrincipalOperation.EVENT_APPEND: {
            "event_batch_sha256": EVENT_BATCH_HASH,
            "expected_revision": 4,
            "mission_id": MISSION_ID,
            "principal_profile_id": PROFILE_ID,
        },
        PrincipalOperation.APPROVAL_SUBMIT: {
            "executor_profile_id": OTHER_PROFILE_ID,
            "idempotency_key_sha256": IDEMPOTENCY_KEY_HASH,
            "mission_id": MISSION_ID,
            "principal_profile_id": PROFILE_ID,
            "proposal_id": "EVT-PHASE4",
            "review_expires_at": "2026-07-30T11:00:00Z",
        },
        PrincipalOperation.APPROVAL_APPROVE: {
            "approval_id": "APR-PHASE4",
            "authority": "range-control",
            "authorization_expires_at": "2026-07-30T11:00:00Z",
            "constraints": ["R1", "R2"],
            "expected_version": 1,
            "idempotency_key_sha256": IDEMPOTENCY_KEY_HASH,
            "principal_profile_id": PROFILE_ID,
        },
        PrincipalOperation.APPROVAL_DENY: {
            "approval_id": "APR-PHASE4",
            "decision_owner": "range-control",
            "expected_version": 1,
            "idempotency_key_sha256": IDEMPOTENCY_KEY_HASH,
            "principal_profile_id": PROFILE_ID,
            "reason": "Scope mismatch",
            "reason_code": "scope_mismatch",
            "risk": "Authorization would exceed scope",
        },
        PrincipalOperation.APPROVAL_REVOKE: {
            "approval_id": "APR-PHASE4",
            "decision_owner": "range-control",
            "expected_version": 2,
            "idempotency_key_sha256": IDEMPOTENCY_KEY_HASH,
            "principal_profile_id": PROFILE_ID,
            "reason": "Authorization withdrawn",
            "reason_code": "authorization_withdrawn",
            "risk": "Authorization is no longer current",
        },
        PrincipalOperation.MISSION_STOP: {
            "decision_owner": "range-control",
            "expected_version": 1,
            "idempotency_key_sha256": IDEMPOTENCY_KEY_HASH,
            "mission_id": MISSION_ID,
            "principal_profile_id": PROFILE_ID,
            "reason": "Operator requested stop",
            "reason_code": "operator_request",
            "risk": "Continued work is not authorized",
        },
        PrincipalOperation.SIMULATION_RUN: {
            "approval_id": "APR-PHASE4",
            "idempotency_key_sha256": IDEMPOTENCY_KEY_HASH,
            "principal_profile_id": PROFILE_ID,
        },
        PrincipalOperation.EXPERT_REVIEW_SNAPSHOT_REGISTER: {
            "active_plan_id": "CLP-" + "A" * 24,
            "active_plan_sha256": MISSION_CONTEXT_HASH,
            "active_plan_version": 1,
            "mission_id": MISSION_ID,
            "mission_revision": 4,
            "principal_profile_id": PROFILE_ID,
            "snapshot_id": "ERS-" + "A" * 32,
            "snapshot_sha256": EVENT_BATCH_HASH,
            "workspace_event_count": 8,
            "workspace_event_head_sha256": IDEMPOTENCY_KEY_HASH,
            "workspace_id": "EWS-" + "A" * 32,
            "workspace_revision": 7,
            "workspace_schema_version": 2,
            "workspace_sha256": MISSION_CONTEXT_HASH,
        },
        PrincipalOperation.EXPERT_WORK_PRODUCT_REVIEW: {
            "active_plan_id": "CLP-" + "A" * 24,
            "active_plan_sha256": MISSION_CONTEXT_HASH,
            "active_plan_version": 1,
            "mission_id": MISSION_ID,
            "mission_revision": 4,
            "principal_profile_id": PROFILE_ID,
            "product_id": "EWP-" + "A" * 32,
            "product_sha256": EVENT_BATCH_HASH,
            "reviewer_role": "independent_assurance",
            "snapshot_id": "ERS-" + "A" * 32,
            "snapshot_sha256": IDEMPOTENCY_KEY_HASH,
            "submission_id": "ERV-" + "A" * 32,
            "submission_sha256": MISSION_CONTEXT_HASH,
            "work_id": "WORK-PHASE4-REVIEW",
        },
        PrincipalOperation.EXPERT_WORKSPACE_REVIEW_CLOSE: {
            "active_plan_id": "CLP-" + "A" * 24,
            "active_plan_sha256": MISSION_CONTEXT_HASH,
            "active_plan_version": 1,
            "closure_request_id": "ECR-" + "A" * 32,
            "closure_request_sha256": EVENT_BATCH_HASH,
            "expected_disposition": "accepted",
            "mission_id": MISSION_ID,
            "mission_revision": 4,
            "principal_profile_id": PROFILE_ID,
            "review_set_sha256": IDEMPOTENCY_KEY_HASH,
            "snapshot_id": "ERS-" + "A" * 32,
            "snapshot_sha256": MISSION_CONTEXT_HASH,
        },
        PrincipalOperation.EXPERT_WORKSPACE_REVIEW_REVOKE: {
            "active_plan_id": "CLP-" + "A" * 24,
            "active_plan_sha256": MISSION_CONTEXT_HASH,
            "active_plan_version": 1,
            "closure_id": "ERC-" + "A" * 32,
            "closure_sha256": EVENT_BATCH_HASH,
            "mission_id": MISSION_ID,
            "mission_revision": 4,
            "principal_profile_id": PROFILE_ID,
            "reason_code": "review_withdrawn",
            "revocation_core_sha256": IDEMPOTENCY_KEY_HASH,
        },
    }
    replacement_item_id = "WIT-SPEC-" + "A" * 16
    intents.update(
        {
            PrincipalOperation.COLLABORATION_REPLACEMENT_REVIEWER_OWNER_AUTHORIZE: {
                "mission_id": MISSION_ID,
                "mission_context_sha256": MISSION_CONTEXT_HASH,
                "admission_id": "RVA-" + "A" * 32,
                "admission_sha256": EVENT_BATCH_HASH,
                "principal_profile_id": PROFILE_ID,
                "role": "mission_owner",
            },
            PrincipalOperation.COLLABORATION_REPLACEMENT_REVIEWER_CONTROL_APPROVE: {
                "mission_id": MISSION_ID,
                "mission_context_sha256": MISSION_CONTEXT_HASH,
                "admission_id": "RVA-" + "A" * 32,
                "admission_sha256": EVENT_BATCH_HASH,
                "principal_profile_id": PROFILE_ID,
                "role": "independent_control",
            },
            PrincipalOperation.COLLABORATION_PLAN_REPLACEMENT_OWNER_AUTHORIZE: (
                replacement_intent("mission_owner", work_item_id=None)
            ),
            PrincipalOperation.COLLABORATION_PLAN_REPLACEMENT_CONTROL_APPROVE: (
                replacement_intent("independent_control", work_item_id=None)
            ),
            PrincipalOperation.COLLABORATION_PLAN_REPLACEMENT_CURRENT_OWNER_AUTHORIZE: (
                replacement_intent("current_owner", work_item_id=replacement_item_id)
            ),
            PrincipalOperation.COLLABORATION_PLAN_REPLACEMENT_PROPOSED_OWNER_ACCEPT: (
                replacement_intent("proposed_owner", work_item_id=replacement_item_id)
            ),
            PrincipalOperation.COLLABORATION_PLAN_REPLACEMENT_SOURCE_COMMAND_REVIEW: (
                replacement_intent(
                    "source_technical_command",
                    work_item_id=replacement_item_id,
                    command=True,
                )
            ),
            PrincipalOperation.COLLABORATION_PLAN_REPLACEMENT_DESTINATION_COMMAND_REVIEW: (
                replacement_intent(
                    "destination_technical_command",
                    work_item_id=replacement_item_id,
                    command=True,
                )
            ),
            PrincipalOperation.COLLABORATION_PLAN_REPLACEMENT_CURRENT_OWNER_CANCEL: (
                replacement_intent("current_owner", work_item_id=replacement_item_id)
            ),
            PrincipalOperation.COLLABORATION_PLAN_REPLACEMENT_ASSURANCE_APPROVE: (
                replacement_intent("independent_assurance", work_item_id=None)
            ),
            PrincipalOperation.COLLABORATION_PLAN_REPLACEMENT_SECOND_CONTROL_APPROVE: (
                replacement_intent("second_control", work_item_id=None)
            ),
        }
    )
    return dict(intents[operation])


def alternate_intent_value(field_name: str, value: Any) -> Any:
    if field_name.endswith("_sha256"):
        return "sha256:" + ("a" if value[-1] != "a" else "b") * 64
    if field_name == "mission_id":
        return "MISSION-OTHER"
    if field_name == "plan_id" or field_name.endswith("_plan_id"):
        marker = "B" if value[-1] != "B" else "C"
        return "CLP-" + marker * 24
    if field_name == "work_item_id":
        return "WIT-READY-" + "B" * 16
    if field_name == "previous_transition_id":
        return "WLT-" + "B" * 32
    if field_name == "recovery_request_id":
        return "WRQ-" + "B" * 32
    if field_name == "entry_id":
        return "OCE-" + "B" * 32
    if field_name == "preflight_id":
        return "OTP-" + "B" * 32
    if field_name == "request_id":
        return "ETR-" + "B" * 32
    if field_name.endswith("assertion_id"):
        return "PAS-" + ("C" if value[-1] != "C" else "D") * 32
    if field_name == "affected_work_item_ids":
        return sorted([*value, "WIT-READY-" + "B" * 16])
    if field_name.endswith("profile_id"):
        return (
            OTHER_PROFILE_ID
            if value != OTHER_PROFILE_ID
            else PROFILE_ID
        )
    if field_name == "expected_revision":
        return 5 if value != 5 else 6
    if field_name == "expected_version":
        return value + 1
    if field_name in {
        "additional_attempts",
        "claim_generation",
        "expected_generation",
        "requested_attempts",
    }:
        return 2 if value == 3 else value + 1
    if field_name == "recovery_epoch":
        return value + 1
    if field_name == "proposal_id":
        return "EVT-OTHER"
    if field_name == "approval_id":
        return "APR-OTHER"
    if field_name == "admission_id":
        return "RVA-" + ("B" if value[-1] != "B" else "C") * 32
    if field_name.endswith("_at"):
        return "2026-07-30T11:30:00Z"
    if field_name == "constraints":
        return [*value, "R3"]
    if field_name == "expected_disposition":
        return "rejected" if value != "rejected" else "accepted"
    if field_name == "reviewer_role":
        return "independent_control"
    if field_name == "role" and value in {
        "typed_resolver",
        "mission_owner",
        "independent_control",
        "admission_control",
    }:
        return (
            "mission_owner"
            if value != "mission_owner"
            else "independent_control"
        )
    if isinstance(value, int) and not isinstance(value, bool):
        return value + 1
    return f"{value}-other"


class CredentialFactory:
    def __init__(self) -> None:
        self.root_private = Ed25519PrivateKey.generate()
        self.scope_private = Ed25519PrivateKey.generate()
        self.assertion_private = Ed25519PrivateKey.generate()

    def policy(
        self,
        *,
        key_state: str = "active",
        retire_at: str | None = None,
        key_not_before: str = "2026-07-30T09:00:00Z",
        key_not_after: str = "2026-07-30T12:00:00Z",
        max_scope_lifetime_seconds: int = 3600,
        max_assertion_lifetime_seconds: int = 300,
        policy_version: int = 7,
        store_id: str = STORE_ID,
        allowed_profiles: list[str] | None = None,
        allowed_subjects: list[str] | None = None,
        allowed_operations: list[str] | None = None,
    ) -> PrincipalTrustPolicy:
        profiles = allowed_profiles or [OTHER_PROFILE_ID, PROFILE_ID]
        subjects = allowed_subjects or [SUBJECT]
        operations = allowed_operations or [
            PrincipalOperation.APPROVAL_APPROVE.value,
            PrincipalOperation.MISSION_STOP.value,
        ]
        raw: dict[str, Any] = {
            "schema_version": 1,
            "policy_id": POLICY_ID,
            "policy_version": policy_version,
            "issuer": "sunderkey-security",
            "audience": AUDIENCE,
            "store_id": store_id,
            "issued_at": "2026-07-30T09:00:00Z",
            "not_before": "2026-07-30T09:00:00Z",
            "expires_at": "2026-07-30T12:00:00Z",
            "max_scope_lifetime_seconds": max_scope_lifetime_seconds,
            "max_assertion_lifetime_seconds": max_assertion_lifetime_seconds,
            "allowed_profiles": sorted(profiles),
            "allowed_subjects": sorted(subjects),
            "allowed_operations": sorted(operations),
            "keys": [
                {
                    "key_id": ASSERTION_KEY_ID,
                    "issuer": "identity-provider",
                    "public_key": b64url(public_bytes(self.assertion_private)),
                    "key_use": TrustKeyUse.PRINCIPAL_ASSERTION.value,
                    "state": key_state,
                    "not_before": key_not_before,
                    "not_after": key_not_after,
                    "retire_at": retire_at,
                    "allowed_profiles": sorted(profiles),
                    "allowed_subjects": sorted(subjects),
                    "allowed_operations": sorted(operations),
                },
                {
                    "key_id": SCOPE_KEY_ID,
                    "issuer": "scope-authority",
                    "public_key": b64url(public_bytes(self.scope_private)),
                    "key_use": TrustKeyUse.SCOPE_GRANT.value,
                    "state": key_state,
                    "not_before": key_not_before,
                    "not_after": key_not_after,
                    "retire_at": retire_at,
                    "allowed_profiles": sorted(profiles),
                    "allowed_subjects": sorted(subjects),
                    "allowed_operations": sorted(operations),
                }
            ],
            "root_key_id": ROOT_KEY_ID,
            "signature": ZERO_SIGNATURE,
        }
        unsigned = PrincipalTrustPolicy.from_dict(raw)
        signature = b64url(self.root_private.sign(unsigned.signing_bytes()))
        return replace(unsigned, signature=signature)

    def verified_policy(self, **kwargs: Any):
        policy = self.policy(**kwargs)
        return verify_trust_policy(
            policy,
            {ROOT_KEY_ID: public_bytes(self.root_private)},
            expected_audience=AUDIENCE,
            expected_store_id=STORE_ID,
            expected_root_key_id=ROOT_KEY_ID,
            minimum_policy_version=7,
            clock=lambda: NOW,
        )

    def grant(
        self,
        *,
        grant_id: str = GRANT_ID,
        profile_id: str = PROFILE_ID,
        subject: str = SUBJECT,
        audience: str = AUDIENCE,
        store_id: str = STORE_ID,
        mission_id: str = MISSION_ID,
        mission_context_hash: str = MISSION_CONTEXT_HASH,
        scope_reference: str = SCOPE_REFERENCE,
        scope_document_hash: str = SCOPE_DOCUMENT_HASH,
        environment: str = "test",
        max_action_tier: str = "R3",
        constraints_hash: str = CONSTRAINTS_HASH,
        operations: list[str] | None = None,
        issued_at: str = "2026-07-30T10:00:00Z",
        not_before: str = "2026-07-30T10:00:00Z",
        expires_at: str = "2026-07-30T10:30:00Z",
        policy_version: int = 7,
        key_id: str = SCOPE_KEY_ID,
        issuer: str = "scope-authority",
        signing_private: Ed25519PrivateKey | None = None,
    ) -> ScopeGrant:
        raw = {
            "schema_version": 1,
            "grant_id": grant_id,
            "policy_id": POLICY_ID,
            "policy_version": policy_version,
            "issuer": issuer,
            "key_id": key_id,
            "subject": subject,
            "profile_id": profile_id,
            "audience": audience,
            "store_id": store_id,
            "mission_id": mission_id,
            "mission_context_hash": mission_context_hash,
            "scope_reference": scope_reference,
            "scope_document_hash": scope_document_hash,
            "environment": environment,
            "max_action_tier": max_action_tier,
            "constraints_hash": constraints_hash,
            "operations": sorted(
                operations
                or [
                    PrincipalOperation.APPROVAL_APPROVE.value,
                    PrincipalOperation.MISSION_STOP.value,
                ]
            ),
            "issued_at": issued_at,
            "not_before": not_before,
            "expires_at": expires_at,
            "signature": ZERO_SIGNATURE,
        }
        unsigned = ScopeGrant.from_dict(raw)
        return replace(
            unsigned,
            signature=b64url(
                (signing_private or self.scope_private).sign(unsigned.signing_bytes())
            ),
        )

    def verified_scope(
        self,
        policy=None,
        *,
        expected_operation: PrincipalOperation = PrincipalOperation.APPROVAL_APPROVE,
        allow_expired_for_safety_reduction: bool = False,
        **kwargs: Any,
    ):
        verified_policy = policy or self.verified_policy()
        grant = self.grant(**kwargs)
        return self.verify_grant(
            grant,
            verified_policy,
            expected_operation=expected_operation,
            allow_expired_for_safety_reduction=allow_expired_for_safety_reduction,
        )

    def verify_grant(
        self,
        grant: ScopeGrant,
        policy=None,
        *,
        expected_audience: str = AUDIENCE,
        expected_store_id: str = STORE_ID,
        expected_mission_id: str = MISSION_ID,
        expected_mission_context_hash: str = MISSION_CONTEXT_HASH,
        expected_scope_reference: str = SCOPE_REFERENCE,
        expected_scope_document_hash: str = SCOPE_DOCUMENT_HASH,
        expected_environment: str = "test",
        expected_max_action_tier: str = "R3",
        expected_constraints_hash: str = CONSTRAINTS_HASH,
        expected_operation: PrincipalOperation = PrincipalOperation.APPROVAL_APPROVE,
        allow_expired_for_safety_reduction: bool = False,
        clock: Any = None,
    ):
        verified_policy = policy or self.verified_policy()
        return verify_scope_grant(
            grant,
            verified_policy,
            expected_audience=expected_audience,
            expected_store_id=expected_store_id,
            expected_mission_id=expected_mission_id,
            expected_mission_context_hash=expected_mission_context_hash,
            expected_scope_reference=expected_scope_reference,
            expected_scope_document_hash=expected_scope_document_hash,
            expected_environment=expected_environment,
            expected_max_action_tier=expected_max_action_tier,
            expected_constraints_hash=expected_constraints_hash,
            expected_operation=expected_operation,
            allow_expired_for_safety_reduction=allow_expired_for_safety_reduction,
            clock=clock or (lambda: NOW),
        )

    def intent_hash(
        self,
        operation: PrincipalOperation = PrincipalOperation.APPROVAL_APPROVE,
    ) -> str:
        return compute_operation_intent_hash(
            operation,
            operation_intent(operation),
        )

    def assertion(
        self,
        *,
        grant=None,
        assertion_id: str = ASSERTION_ID,
        policy_id: str = POLICY_ID,
        policy_version: int = 7,
        scope_grant_id: str = GRANT_ID,
        scope_grant_sha256: str | None = None,
        subject: str = SUBJECT,
        profile_id: str = PROFILE_ID,
        audience: str = AUDIENCE,
        store_id: str = STORE_ID,
        mission_id: str = MISSION_ID,
        operation: PrincipalOperation = PrincipalOperation.APPROVAL_APPROVE,
        operation_intent_sha256: str | None = None,
        issued_at: str = "2026-07-30T10:04:00Z",
        not_before: str = "2026-07-30T10:04:00Z",
        expires_at: str = "2026-07-30T10:09:00Z",
    ) -> PrincipalAssertion:
        scope = grant or self.grant()
        raw = {
            "schema_version": 1,
            "assertion_id": assertion_id,
            "policy_id": policy_id,
            "policy_version": policy_version,
            "scope_grant_id": scope_grant_id,
            "scope_grant_sha256": scope_grant_sha256 or scope.content_sha256,
            "issuer": "identity-provider",
            "key_id": ASSERTION_KEY_ID,
            "subject": subject,
            "profile_id": profile_id,
            "audience": audience,
            "store_id": store_id,
            "mission_id": mission_id,
            "operation": operation.value,
            "operation_intent_sha256": operation_intent_sha256 or self.intent_hash(operation),
            "issued_at": issued_at,
            "not_before": not_before,
            "expires_at": expires_at,
            "signature": ZERO_SIGNATURE,
        }
        unsigned = PrincipalAssertion.from_dict(raw)
        return replace(
            unsigned,
            signature=b64url(self.assertion_private.sign(unsigned.signing_bytes())),
        )

    def verify_assertion(
        self,
        assertion: PrincipalAssertion,
        *,
        policy=None,
        scope=None,
        expected_audience: str = AUDIENCE,
        expected_store_id: str = STORE_ID,
        expected_mission_id: str = MISSION_ID,
        expected_operation: PrincipalOperation = PrincipalOperation.APPROVAL_APPROVE,
        expected_intent_hash: str | None = None,
        clock=lambda: NOW,
    ):
        verified_policy = policy or self.verified_policy()
        verified_scope = scope or self.verified_scope(
            verified_policy,
            expected_operation=expected_operation,
        )
        return verify_principal_assertion(
            assertion,
            verified_policy,
            verified_scope,
            expected_audience=expected_audience,
            expected_store_id=expected_store_id,
            expected_mission_id=expected_mission_id,
            expected_operation=expected_operation,
            expected_operation_intent_sha256=expected_intent_hash or self.intent_hash(),
            clock=clock,
        )


class IdentityVerificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.factory = CredentialFactory()

    def test_valid_chain_derives_authenticated_principal(self) -> None:
        verified_policy = self.factory.verified_policy()
        grant = self.factory.grant()
        verified_scope = self.factory.verify_grant(grant, verified_policy)
        assertion = self.factory.assertion(grant=grant)
        principal = self.factory.verify_assertion(
            assertion,
            policy=verified_policy,
            scope=verified_scope,
        )

        self.assertEqual(principal.subject, SUBJECT)
        self.assertEqual(principal.profile_id, PROFILE_ID)
        self.assertEqual(principal.operation, PrincipalOperation.APPROVAL_APPROVE)
        self.assertEqual(principal.scope_grant_sha256, grant.content_sha256)
        self.assertEqual(principal.authenticated_at, "2026-07-30T10:05:00Z")
        self.assertTrue(principal.assertion_sha256.startswith("sha256:"))
        self.assertNotIn("signature", principal.to_dict())

    def test_rfc8032_vector_one_passes_strict_verification(self) -> None:
        public_key = bytes.fromhex(
            "d75a980182b10ab7d54bfed3c964073a"
            "0ee172f3daa62325af021a68f707511a"
        )
        signature = bytes.fromhex(
            "e5564300c360ac729086e2cc806e828a"
            "84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46b"
            "d25bf5f0595bbe24655141438e7a100b"
        )
        _strict_ed25519_public_key(public_key, "RFC 8032 key")
        _verify_ed25519(
            public_key,
            b64url(signature),
            b"",
            "RFC 8032 vector 1",
        )

    def test_policy_requires_separately_trusted_root_key(self) -> None:
        policy = self.factory.policy()
        with self.assertRaisesRegex(PrincipalAuthenticationError, "not trusted"):
            verify_trust_policy(
                policy,
                {},
                expected_audience=AUDIENCE,
                expected_store_id=STORE_ID,
                expected_root_key_id=ROOT_KEY_ID,
                minimum_policy_version=7,
                clock=lambda: NOW,
            )

    def test_policy_is_store_bound_and_rejects_version_rollback(self) -> None:
        policy = self.factory.policy()
        root_keys = {ROOT_KEY_ID: public_bytes(self.factory.root_private)}
        with self.assertRaisesRegex(PrincipalAuthenticationError, "store does not match"):
            verify_trust_policy(
                policy,
                root_keys,
                expected_audience=AUDIENCE,
                expected_store_id=OTHER_STORE_ID,
                expected_root_key_id=ROOT_KEY_ID,
                minimum_policy_version=7,
                clock=lambda: NOW,
            )
        with self.assertRaisesRegex(PrincipalAuthenticationError, "older"):
            verify_trust_policy(
                policy,
                root_keys,
                expected_audience=AUDIENCE,
                expected_store_id=STORE_ID,
                expected_root_key_id=ROOT_KEY_ID,
                minimum_policy_version=8,
                clock=lambda: NOW,
            )

        wrong_root = Ed25519PrivateKey.generate()
        with self.assertRaisesRegex(PrincipalAuthenticationError, "signature verification failed"):
            verify_trust_policy(
                policy,
                {ROOT_KEY_ID: public_bytes(wrong_root)},
                expected_audience=AUDIENCE,
                expected_store_id=STORE_ID,
                expected_root_key_id=ROOT_KEY_ID,
                minimum_policy_version=7,
                clock=lambda: NOW,
            )

    def test_root_selection_is_explicit_and_key_material_is_separated(self) -> None:
        policy = self.factory.policy()
        other_root = Ed25519PrivateKey.generate()
        with self.assertRaisesRegex(
            PrincipalAuthenticationError,
            "expected root",
        ):
            verify_trust_policy(
                policy,
                {
                    ROOT_KEY_ID: public_bytes(self.factory.root_private),
                    "ROOT-OTHER": public_bytes(other_root),
                },
                expected_audience=AUDIENCE,
                expected_store_id=STORE_ID,
                expected_root_key_id="ROOT-OTHER",
                minimum_policy_version=7,
                clock=lambda: NOW,
            )

        raw = policy.to_dict()
        raw["keys"][0]["public_key"] = b64url(
            public_bytes(self.factory.root_private)
        )
        raw["signature"] = ZERO_SIGNATURE
        unsigned = PrincipalTrustPolicy.from_dict(raw)
        root_reused = replace(
            unsigned,
            signature=b64url(
                self.factory.root_private.sign(unsigned.signing_bytes())
            ),
        )
        with self.assertRaisesRegex(
            PrincipalAuthenticationError,
            "reuse root key material",
        ):
            verify_trust_policy(
                root_reused,
                {ROOT_KEY_ID: public_bytes(self.factory.root_private)},
                expected_audience=AUDIENCE,
                expected_store_id=STORE_ID,
                expected_root_key_id=ROOT_KEY_ID,
                minimum_policy_version=7,
                clock=lambda: NOW,
            )

    def test_weak_ed25519_points_and_noncanonical_signatures_are_rejected(self) -> None:
        policy = self.factory.policy()
        weak_roots = (
            bytes(32),
            IDENTITY_POINT,
            (2**255 - 19).to_bytes(32, "little"),
        )
        for weak_root in weak_roots:
            forged = replace(policy, signature=IDENTITY_SIGNATURE)
            with (
                self.subTest(weak_root=weak_root.hex()),
                self.assertRaisesRegex(
                    PrincipalAuthenticationError,
                    "prime-order",
                ),
            ):
                verify_trust_policy(
                    forged,
                    {ROOT_KEY_ID: weak_root},
                    expected_audience=AUDIENCE,
                    expected_store_id=STORE_ID,
                    expected_root_key_id=ROOT_KEY_ID,
                    minimum_policy_version=7,
                    clock=lambda: NOW,
                )

        with self.assertRaisesRegex(
            PrincipalAuthenticationError,
            "strict canonical",
        ):
            verify_trust_policy(
                replace(policy, signature=IDENTITY_SIGNATURE),
                {ROOT_KEY_ID: public_bytes(self.factory.root_private)},
                expected_audience=AUDIENCE,
                expected_store_id=STORE_ID,
                expected_root_key_id=ROOT_KEY_ID,
                minimum_policy_version=7,
                clock=lambda: NOW,
            )

        signature_bytes = base64.urlsafe_b64decode(policy.signature + "==")
        noncanonical_s = b64url(
            signature_bytes[:32]
            + ED25519_SUBGROUP_ORDER.to_bytes(32, "little")
        )
        with self.assertRaisesRegex(
            PrincipalAuthenticationError,
            "strict canonical",
        ):
            verify_trust_policy(
                replace(policy, signature=noncanonical_s),
                {ROOT_KEY_ID: public_bytes(self.factory.root_private)},
                expected_audience=AUDIENCE,
                expected_store_id=STORE_ID,
                expected_root_key_id=ROOT_KEY_ID,
                minimum_policy_version=7,
                clock=lambda: NOW,
            )

        raw = policy.to_dict()
        raw["keys"][0]["public_key"] = b64url(IDENTITY_POINT)
        with self.assertRaisesRegex(
            PrincipalAuthenticationError,
            "prime-order",
        ):
            PrincipalTrustPolicy.from_dict(raw)

        verified_policy = self.factory.verified_policy()
        grant = self.factory.grant()
        with self.assertRaisesRegex(
            PrincipalAuthenticationError,
            "strict canonical",
        ):
            self.factory.verify_grant(
                replace(grant, signature=IDENTITY_SIGNATURE),
                verified_policy,
            )

        verified_scope = self.factory.verify_grant(
            grant,
            verified_policy,
        )
        assertion = self.factory.assertion(grant=grant)
        with self.assertRaisesRegex(
            PrincipalAuthenticationError,
            "strict canonical",
        ):
            self.factory.verify_assertion(
                replace(assertion, signature=IDENTITY_SIGNATURE),
                policy=verified_policy,
                scope=verified_scope,
            )

    def test_verified_wrappers_reject_direct_replacement(self) -> None:
        verified_policy = self.factory.verified_policy()
        grant = self.factory.grant()
        verified_scope = self.factory.verify_grant(
            grant,
            verified_policy,
        )
        assertion = self.factory.assertion(grant=grant)
        principal = self.factory.verify_assertion(
            assertion,
            policy=verified_policy,
            scope=verified_scope,
        )

        with self.assertRaisesRegex(TypeError, "verify_trust_policy"):
            replace(
                verified_policy,
                policy_sha256="sha256:" + "0" * 64,
            )
        with self.assertRaisesRegex(TypeError, "verify_scope_grant"):
            replace(
                verified_scope,
                verified_operation=PrincipalOperation.MISSION_STOP,
            )
        with self.assertRaisesRegex(TypeError, "verify_principal_assertion"):
            replace(principal, profile_id=OTHER_PROFILE_ID)

    def test_signature_tampering_is_rejected(self) -> None:
        grant = self.factory.grant()
        assertion = self.factory.assertion(grant=grant)
        tampered = replace(assertion, assertion_id=OTHER_ASSERTION_ID)

        with self.assertRaisesRegex(PrincipalAuthenticationError, "signature verification failed"):
            self.factory.verify_assertion(tampered)

    def test_runtime_binding_mismatches_fail_closed(self) -> None:
        verified_policy = self.factory.verified_policy()
        grant = self.factory.grant()
        verified_scope = self.factory.verified_scope(verified_policy)
        assertion = self.factory.assertion(grant=grant)
        different_intent = operation_intent(
            PrincipalOperation.APPROVAL_APPROVE
        )
        different_intent["approval_id"] = "APR-DIFFERENT"

        cases = (
            {"expected_audience": "another-runtime"},
            {"expected_store_id": OTHER_STORE_ID},
            {"expected_mission_id": "MISSION-OTHER"},
            {"expected_operation": PrincipalOperation.MISSION_STOP},
            {
                "expected_intent_hash": compute_operation_intent_hash(
                    PrincipalOperation.APPROVAL_APPROVE,
                    different_intent,
                )
            },
        )
        for arguments in cases:
            with (
                self.subTest(arguments=arguments),
                self.assertRaises(PrincipalAuthenticationError),
            ):
                self.factory.verify_assertion(
                    assertion,
                    policy=verified_policy,
                    scope=verified_scope,
                    **arguments,
                )

    def test_scope_grant_runtime_bindings_fail_closed(self) -> None:
        verified_policy = self.factory.verified_policy()
        cases = (
            {"expected_audience": "another-runtime"},
            {"expected_store_id": OTHER_STORE_ID},
            {"expected_mission_id": "MISSION-OTHER"},
            {"expected_mission_context_hash": "sha256:" + "4" * 64},
            {"expected_scope_reference": "SCOPE-OTHER"},
            {"expected_scope_document_hash": "sha256:" + "5" * 64},
            {"expected_environment": "production"},
            {"expected_max_action_tier": "R2"},
            {"expected_constraints_hash": "sha256:" + "6" * 64},
        )
        for arguments in cases:
            with (
                self.subTest(arguments=arguments),
                self.assertRaises(PrincipalAuthenticationError),
            ):
                self.factory.verify_grant(
                    self.factory.grant(),
                    verified_policy,
                    expected_audience=arguments.get("expected_audience", AUDIENCE),
                    expected_store_id=arguments.get("expected_store_id", STORE_ID),
                    expected_mission_id=arguments.get("expected_mission_id", MISSION_ID),
                    expected_mission_context_hash=arguments.get(
                        "expected_mission_context_hash",
                        MISSION_CONTEXT_HASH,
                    ),
                    expected_scope_reference=arguments.get(
                        "expected_scope_reference",
                        SCOPE_REFERENCE,
                    ),
                    expected_scope_document_hash=arguments.get(
                        "expected_scope_document_hash",
                        SCOPE_DOCUMENT_HASH,
                    ),
                    expected_environment=arguments.get("expected_environment", "test"),
                    expected_max_action_tier=arguments.get(
                        "expected_max_action_tier",
                        "R3",
                    ),
                    expected_constraints_hash=arguments.get(
                        "expected_constraints_hash",
                        CONSTRAINTS_HASH,
                    ),
                )

    def test_key_use_confusion_is_rejected_before_signature_acceptance(self) -> None:
        verified_policy = self.factory.verified_policy()
        wrong_key_grant = self.factory.grant(
            key_id=ASSERTION_KEY_ID,
            issuer="identity-provider",
            signing_private=self.factory.assertion_private,
        )
        with self.assertRaisesRegex(
            PrincipalAuthenticationError,
            "cannot verify a scope_grant",
        ):
            self.factory.verify_grant(wrong_key_grant, verified_policy)

        grant = self.factory.grant()
        verified_scope = self.factory.verify_grant(grant, verified_policy)
        assertion = self.factory.assertion(grant=grant)
        assertion_raw = assertion.to_dict()
        assertion_raw["key_id"] = SCOPE_KEY_ID
        assertion_raw["issuer"] = "scope-authority"
        unsigned = PrincipalAssertion.from_dict(
            {**assertion_raw, "signature": ZERO_SIGNATURE}
        )
        wrong_key_assertion = replace(
            unsigned,
            signature=b64url(self.factory.scope_private.sign(unsigned.signing_bytes())),
        )
        with self.assertRaisesRegex(
            PrincipalAuthenticationError,
            "cannot verify a principal_assertion",
        ):
            self.factory.verify_assertion(
                wrong_key_assertion,
                policy=verified_policy,
                scope=verified_scope,
            )

    def test_expired_scope_can_only_reduce_safety_authority(self) -> None:
        verified_policy = self.factory.verified_policy()
        expired_stop_grant = self.factory.grant(
            operations=[PrincipalOperation.MISSION_STOP.value],
            expires_at="2026-07-30T10:03:00Z",
        )
        with self.assertRaisesRegex(PrincipalAuthenticationError, "expired"):
            self.factory.verify_grant(
                expired_stop_grant,
                verified_policy,
                expected_operation=PrincipalOperation.MISSION_STOP,
            )

        safety_scope = self.factory.verify_grant(
            expired_stop_grant,
            verified_policy,
            expected_operation=PrincipalOperation.MISSION_STOP,
            allow_expired_for_safety_reduction=True,
        )
        self.assertFalse(safety_scope.scope_active)
        self.assertTrue(safety_scope.safety_reduction_only)
        stop_assertion = self.factory.assertion(
            grant=expired_stop_grant,
            operation=PrincipalOperation.MISSION_STOP,
            operation_intent_sha256=self.factory.intent_hash(
                PrincipalOperation.MISSION_STOP
            ),
            issued_at="2026-07-30T10:02:00Z",
            not_before="2026-07-30T10:02:00Z",
            expires_at="2026-07-30T10:07:00Z",
        )
        principal = self.factory.verify_assertion(
            stop_assertion,
            policy=verified_policy,
            scope=safety_scope,
            expected_operation=PrincipalOperation.MISSION_STOP,
            expected_intent_hash=self.factory.intent_hash(
                PrincipalOperation.MISSION_STOP
            ),
        )
        self.assertEqual(principal.operation, PrincipalOperation.MISSION_STOP)

        expired_non_stop_grants = (
            self.factory.grant(
                operations=[PrincipalOperation.APPROVAL_APPROVE.value],
                expires_at="2026-07-30T10:03:00Z",
            ),
            self.factory.grant(
                operations=[PrincipalOperation.APPROVAL_DENY.value],
                expires_at="2026-07-30T10:03:00Z",
            ),
            self.factory.grant(
                operations=[PrincipalOperation.APPROVAL_REVOKE.value],
                expires_at="2026-07-30T10:03:00Z",
            ),
        )
        for expired_grant in expired_non_stop_grants:
            with (
                self.subTest(operation=expired_grant.operations[0]),
                self.assertRaisesRegex(
                    PrincipalAuthenticationError,
                    "expired",
                ),
            ):
                self.factory.verify_grant(
                    expired_grant,
                    verified_policy,
                    expected_operation=expired_grant.operations[0],
                    allow_expired_for_safety_reduction=True,
                )

        stale_assertion = self.factory.assertion(
            grant=expired_stop_grant,
            operation=PrincipalOperation.MISSION_STOP,
            operation_intent_sha256=self.factory.intent_hash(
                PrincipalOperation.MISSION_STOP
            ),
            issued_at="2026-07-30T10:04:00Z",
            not_before="2026-07-30T10:04:00Z",
            expires_at="2026-07-30T10:08:00Z",
        )
        with self.assertRaisesRegex(
            PrincipalAuthenticationError,
            "issued before",
        ):
            self.factory.verify_assertion(
                stale_assertion,
                policy=verified_policy,
                scope=safety_scope,
                expected_operation=PrincipalOperation.MISSION_STOP,
                expected_intent_hash=self.factory.intent_hash(
                    PrincipalOperation.MISSION_STOP
                ),
            )

        delayed_assertion = self.factory.assertion(
            grant=expired_stop_grant,
            operation=PrincipalOperation.MISSION_STOP,
            operation_intent_sha256=self.factory.intent_hash(
                PrincipalOperation.MISSION_STOP
            ),
            issued_at="2026-07-30T10:02:00Z",
            not_before="2026-07-30T10:04:00Z",
            expires_at="2026-07-30T10:07:00Z",
        )
        with self.assertRaisesRegex(
            PrincipalAuthenticationError,
            "become active before",
        ):
            self.factory.verify_assertion(
                delayed_assertion,
                policy=verified_policy,
                scope=safety_scope,
                expected_operation=PrincipalOperation.MISSION_STOP,
                expected_intent_hash=self.factory.intent_hash(
                    PrincipalOperation.MISSION_STOP
                ),
            )

        outside_grace_grant = self.factory.grant(
            operations=[PrincipalOperation.MISSION_STOP.value],
            expires_at="2026-07-30T10:03:00Z",
        )
        with self.assertRaisesRegex(
            PrincipalAuthenticationError,
            "grace period",
        ):
            self.factory.verify_grant(
                outside_grace_grant,
                verified_policy,
                expected_operation=PrincipalOperation.MISSION_STOP,
                allow_expired_for_safety_reduction=True,
                clock=lambda: datetime(
                    2026,
                    7,
                    30,
                    10,
                    8,
                    tzinfo=UTC,
                ),
            )

    def test_scope_hash_and_identity_mismatches_fail_closed(self) -> None:
        verified_policy = self.factory.verified_policy()
        grant = self.factory.grant()
        verified_scope = self.factory.verified_scope(verified_policy)
        mismatched_hash = "sha256:" + "0" * 64
        assertions = (
            self.factory.assertion(grant=grant, scope_grant_id=OTHER_GRANT_ID),
            self.factory.assertion(grant=grant, scope_grant_sha256=mismatched_hash),
            self.factory.assertion(grant=grant, subject=OTHER_SUBJECT),
            self.factory.assertion(grant=grant, profile_id=OTHER_PROFILE_ID),
        )
        for assertion in assertions:
            with (
                self.subTest(assertion=assertion.assertion_id),
                self.assertRaises(PrincipalAuthenticationError),
            ):
                self.factory.verify_assertion(
                    assertion,
                    policy=verified_policy,
                    scope=verified_scope,
                )

    def test_credentials_are_bound_to_exact_policy_version(self) -> None:
        verified_policy = self.factory.verified_policy()
        old_grant = self.factory.grant(policy_version=6)
        with self.assertRaisesRegex(PrincipalAuthenticationError, "policy version"):
            self.factory.verify_grant(old_grant, verified_policy)

        grant = self.factory.grant()
        verified_scope = self.factory.verify_grant(grant, verified_policy)
        old_assertion = self.factory.assertion(grant=grant, policy_version=6)
        with self.assertRaisesRegex(PrincipalAuthenticationError, "policy version"):
            self.factory.verify_assertion(
                old_assertion,
                policy=verified_policy,
                scope=verified_scope,
            )

    def test_exact_policy_and_key_allowlists_are_enforced(self) -> None:
        verified_policy = self.factory.verified_policy(
            allowed_profiles=[PROFILE_ID],
            allowed_subjects=[SUBJECT],
            allowed_operations=[PrincipalOperation.APPROVAL_APPROVE.value],
        )
        cases = (
            self.factory.grant(profile_id=OTHER_PROFILE_ID),
            self.factory.grant(subject=OTHER_SUBJECT),
            self.factory.grant(operations=[PrincipalOperation.MISSION_STOP.value]),
        )
        for grant in cases:
            with (
                self.subTest(grant=grant.to_dict()),
                self.assertRaisesRegex(PrincipalAuthenticationError, "exactly allowed"),
            ):
                self.factory.verify_grant(
                    grant,
                    verified_policy,
                    expected_operation=grant.operations[0],
                )

    def test_revoked_key_is_never_accepted(self) -> None:
        verified_policy = self.factory.verified_policy(key_state="revoked")
        with self.assertRaisesRegex(PrincipalAuthenticationError, "revoked"):
            self.factory.verified_scope(verified_policy)

    def test_retiring_key_accepts_only_credentials_issued_by_retirement(self) -> None:
        verified_policy = self.factory.verified_policy(
            key_state="retiring",
            retire_at="2026-07-30T10:01:00Z",
        )
        accepted = self.factory.grant(
            issued_at="2026-07-30T10:00:00Z",
            not_before="2026-07-30T10:00:00Z",
        )
        self.factory.verify_grant(
            accepted,
            verified_policy,
            clock=lambda: datetime(
                2026,
                7,
                30,
                10,
                0,
                30,
                tzinfo=UTC,
            ),
        )
        with self.assertRaisesRegex(
            PrincipalAuthenticationError,
            "retirement cutoff",
        ):
            self.factory.verify_grant(accepted, verified_policy)

        rejected = self.factory.grant(
            issued_at="2026-07-30T10:01:00Z",
            not_before="2026-07-30T10:01:00Z",
        )
        with self.assertRaisesRegex(PrincipalAuthenticationError, "after.*retirement"):
            self.factory.verify_grant(rejected, verified_policy)

    def test_key_cryptoperiod_is_enforced_at_verification_time(self) -> None:
        verified_policy = self.factory.verified_policy(
            key_not_after="2026-07-30T10:05:00Z",
        )
        with self.assertRaisesRegex(PrincipalAuthenticationError, "not currently valid"):
            self.factory.verified_scope(verified_policy)

    def test_cached_scope_is_revalidated_at_principal_verification_time(self) -> None:
        verified_policy = self.factory.verified_policy(
            key_not_after="2026-07-30T10:06:00Z",
        )
        grant = self.factory.grant()
        verified_scope = self.factory.verify_grant(
            grant,
            verified_policy,
        )
        assertion = self.factory.assertion(grant=grant)
        with self.assertRaisesRegex(
            PrincipalAuthenticationError,
            "not currently valid",
        ):
            self.factory.verify_assertion(
                assertion,
                policy=verified_policy,
                scope=verified_scope,
                clock=lambda: datetime(
                    2026,
                    7,
                    30,
                    10,
                    7,
                    tzinfo=UTC,
                ),
            )

    def test_expiry_is_exclusive(self) -> None:
        verified_policy = self.factory.verified_policy()
        grant = self.factory.grant(expires_at="2026-07-30T10:05:00Z")
        with self.assertRaisesRegex(PrincipalAuthenticationError, "expired"):
            self.factory.verify_grant(grant, verified_policy)

    def test_max_scope_and_assertion_lifetimes_are_enforced(self) -> None:
        short_scope_policy = self.factory.verified_policy(max_scope_lifetime_seconds=60)
        with self.assertRaisesRegex(PrincipalAuthenticationError, "maximum lifetime"):
            self.factory.verified_scope(short_scope_policy)

        short_assertion_policy = self.factory.verified_policy(max_assertion_lifetime_seconds=60)
        verified_scope = self.factory.verified_scope(short_assertion_policy)
        assertion = self.factory.assertion()
        with self.assertRaisesRegex(PrincipalAuthenticationError, "maximum lifetime"):
            self.factory.verify_assertion(
                assertion,
                policy=short_assertion_policy,
                scope=verified_scope,
            )

    def test_assertion_cannot_outlive_scope(self) -> None:
        verified_policy = self.factory.verified_policy()
        grant = self.factory.grant(expires_at="2026-07-30T10:06:00Z")
        verified_scope = self.factory.verified_scope(verified_policy, expires_at=grant.expires_at)
        assertion = self.factory.assertion(grant=grant, expires_at="2026-07-30T10:07:00Z")
        with self.assertRaisesRegex(PrincipalAuthenticationError, "after its scope grant"):
            self.factory.verify_assertion(
                assertion,
                policy=verified_policy,
                scope=verified_scope,
            )

    def test_operation_intent_hash_is_domain_and_operation_bound(self) -> None:
        request = operation_intent(PrincipalOperation.APPROVAL_APPROVE)
        first = compute_operation_intent_hash(
            PrincipalOperation.APPROVAL_APPROVE,
            request,
        )
        same = compute_operation_intent_hash(
            PrincipalOperation.APPROVAL_APPROVE.value,
            dict(reversed(tuple(request.items()))),
        )
        other = compute_operation_intent_hash(
            PrincipalOperation.APPROVAL_DENY,
            operation_intent(PrincipalOperation.APPROVAL_DENY),
        )
        self.assertEqual(first, same)
        self.assertNotEqual(first, other)
        self.assertRegex(first, r"^sha256:[0-9a-f]{64}$")

        invalid = operation_intent(PrincipalOperation.APPROVAL_APPROVE)
        invalid["expected_version"] = 0.5
        with self.assertRaisesRegex(PrincipalAuthenticationError, "integer"):
            compute_operation_intent_hash(
                PrincipalOperation.APPROVAL_APPROVE,
                invalid,
            )

    def test_every_operation_intent_contract_is_closed_and_field_bound(self) -> None:
        for operation in PrincipalOperation:
            request = operation_intent(operation)
            baseline = compute_operation_intent_hash(operation, request)

            missing = dict(request)
            missing.pop(next(iter(missing)))
            with (
                self.subTest(operation=operation, case="missing"),
                self.assertRaisesRegex(
                    PrincipalAuthenticationError,
                    "missing required fields",
                ),
            ):
                compute_operation_intent_hash(operation, missing)

            extra = {**request, "unreviewed_field": "value"}
            with (
                self.subTest(operation=operation, case="extra"),
                self.assertRaisesRegex(
                    PrincipalAuthenticationError,
                    "unknown fields",
                ),
            ):
                compute_operation_intent_hash(operation, extra)

            wrong_type = dict(request)
            wrong_type[next(iter(wrong_type))] = None
            with (
                self.subTest(operation=operation, case="wrong_type"),
                self.assertRaises(PrincipalAuthenticationError),
            ):
                compute_operation_intent_hash(operation, wrong_type)

            for field_name, value in request.items():
                changed = dict(request)
                changed[field_name] = alternate_intent_value(
                    field_name,
                    value,
                )
                with self.subTest(
                    operation=operation,
                    changed_field=field_name,
                ):
                    if (
                        "collaboration.plan-replacement" in operation.value
                        and (field_name == "role" or value is None)
                    ):
                        with self.assertRaises(PrincipalAuthenticationError):
                            compute_operation_intent_hash(operation, changed)
                        continue
                    if (
                        operation is PrincipalOperation.TARGET_HEALTH_GATE_RESUME
                        and field_name == "role"
                    ):
                        with self.assertRaises(PrincipalAuthenticationError):
                            compute_operation_intent_hash(operation, changed)
                        continue
                    self.assertNotEqual(
                        compute_operation_intent_hash(operation, changed),
                        baseline,
                    )


class IdentityGoldenVectorTests(unittest.TestCase):
    def test_deterministic_signing_and_intent_vectors(self) -> None:
        root_private = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("00" * 32))
        scope_private = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("11" * 32))
        assertion_private = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("22" * 32))

        root_public = "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik"
        scope_public = "0EqyMnQrtKs6E2i9RhXk5tAiSrcaAWuvhSCjMsl3hzc"
        assertion_public = "oJql9HpnWYAv-VX43C0qFKXJnSO-l_hkEn_5ODRVpPA"
        self.assertEqual(b64url(public_bytes(root_private)), root_public)
        self.assertEqual(b64url(public_bytes(scope_private)), scope_public)
        self.assertEqual(b64url(public_bytes(assertion_private)), assertion_public)

        policy_raw: dict[str, Any] = {
            "schema_version": 1,
            "policy_id": "POLICY-GOLDEN-V1",
            "policy_version": 42,
            "issuer": "sunderkey-security",
            "audience": "sunderkey-runtime",
            "store_id": "STR-00112233445566778899AABBCCDDEEFF",
            "issued_at": "2030-01-02T03:04:05Z",
            "not_before": "2030-01-02T03:04:05Z",
            "expires_at": "2030-01-03T03:04:05Z",
            "max_scope_lifetime_seconds": 3600,
            "max_assertion_lifetime_seconds": 300,
            "allowed_profiles": ["AOE-HQ-12"],
            "allowed_subjects": ["operator:golden"],
            "allowed_operations": ["sunderkey.mission.stop.v1"],
            "keys": [
                {
                    "key_id": "ASSERTION-GOLDEN-1",
                    "issuer": "identity-provider",
                    "public_key": assertion_public,
                    "key_use": "principal_assertion",
                    "state": "active",
                    "not_before": "2030-01-02T03:04:05Z",
                    "not_after": "2030-01-03T03:04:05Z",
                    "retire_at": None,
                    "allowed_profiles": ["AOE-HQ-12"],
                    "allowed_subjects": ["operator:golden"],
                    "allowed_operations": ["sunderkey.mission.stop.v1"],
                },
                {
                    "key_id": "SCOPE-GOLDEN-1",
                    "issuer": "scope-authority",
                    "public_key": scope_public,
                    "key_use": "scope_grant",
                    "state": "active",
                    "not_before": "2030-01-02T03:04:05Z",
                    "not_after": "2030-01-03T03:04:05Z",
                    "retire_at": None,
                    "allowed_profiles": ["AOE-HQ-12"],
                    "allowed_subjects": ["operator:golden"],
                    "allowed_operations": ["sunderkey.mission.stop.v1"],
                },
            ],
            "root_key_id": "ROOT-GOLDEN-1",
            "signature": ZERO_SIGNATURE,
        }
        unsigned_policy = PrincipalTrustPolicy.from_dict(policy_raw)
        policy_signature = (
            "q4zBHxya55HLjXcrTPCVQEbcD5Zb8KSXdvX5hSOgIuvRmR3yYXGu0MWPtNnkE7Qj"
            "-iHZONXvyv6FoY_Gt-aaCQ"
        )
        self.assertEqual(
            hashlib.sha256(unsigned_policy.signing_bytes()).hexdigest(),
            "ba477574ef5a998cdff79869a0e514ef3f9f5f1e2df630840b367bfec18cc4d2",
        )
        self.assertEqual(
            b64url(root_private.sign(unsigned_policy.signing_bytes())),
            policy_signature,
        )
        policy = replace(unsigned_policy, signature=policy_signature)
        self.assertEqual(
            policy.content_sha256,
            "sha256:24ec7a4c9f4d67b6cb3836604f6e581c91bb62e1b28a112ee8dc6a0a128e9e55",
        )

        grant_raw: dict[str, Any] = {
            "schema_version": 1,
            "grant_id": "SGR-00112233445566778899AABBCCDDEEFF",
            "policy_id": "POLICY-GOLDEN-V1",
            "policy_version": 42,
            "issuer": "scope-authority",
            "key_id": "SCOPE-GOLDEN-1",
            "subject": "operator:golden",
            "profile_id": "AOE-HQ-12",
            "audience": "sunderkey-runtime",
            "store_id": "STR-00112233445566778899AABBCCDDEEFF",
            "mission_id": "MISSION-GOLDEN-1",
            "mission_context_hash": "sha256:" + "11" * 32,
            "scope_reference": "SCOPE-GOLDEN-1",
            "scope_document_hash": "sha256:" + "22" * 32,
            "environment": "test",
            "max_action_tier": "R1",
            "constraints_hash": "sha256:" + "33" * 32,
            "operations": ["sunderkey.mission.stop.v1"],
            "issued_at": "2030-01-02T03:05:00Z",
            "not_before": "2030-01-02T03:05:00Z",
            "expires_at": "2030-01-02T04:05:00Z",
            "signature": ZERO_SIGNATURE,
        }
        unsigned_grant = ScopeGrant.from_dict(grant_raw)
        grant_signature = (
            "V-0LMGpqDQwFT-sJE9aan36g4dmpGuBFYI0YGYgdGuw8SyU9JM_EDAsZNSYMVng"
            "SY5qycBMp8b5a4AbBue9aAQ"
        )
        self.assertEqual(
            hashlib.sha256(unsigned_grant.signing_bytes()).hexdigest(),
            "c8f6c310d587cb24281e790736a5c55bf4056b1cf3b04250a04d8f1d1a7b943d",
        )
        self.assertEqual(
            b64url(scope_private.sign(unsigned_grant.signing_bytes())),
            grant_signature,
        )
        grant = replace(unsigned_grant, signature=grant_signature)
        self.assertEqual(
            grant.content_sha256,
            "sha256:fcfe9390894efed11d24e6f74f6e9f1a893eeb731d46ced835501e0383ca9f2f",
        )

        stop_intent = {
            "decision_owner": "range-control",
            "expected_version": 7,
            "idempotency_key_sha256": "sha256:" + "44" * 32,
            "mission_id": "MISSION-GOLDEN-1",
            "principal_profile_id": "AOE-HQ-12",
            "reason": "Emergency stop requested",
            "reason_code": "emergency_stop",
            "risk": "Continued execution exceeds authorization",
        }
        intent_hash = compute_operation_intent_hash(
            PrincipalOperation.MISSION_STOP,
            stop_intent,
        )
        self.assertEqual(
            intent_hash,
            "sha256:440cce51589764536069145b6258260afe8d06c6c1f7bdac07e23ad450ccff51",
        )

        assertion_raw: dict[str, Any] = {
            "schema_version": 1,
            "assertion_id": "PAS-FFEEDDCCBBAA99887766554433221100",
            "policy_id": "POLICY-GOLDEN-V1",
            "policy_version": 42,
            "scope_grant_id": "SGR-00112233445566778899AABBCCDDEEFF",
            "scope_grant_sha256": (
                "sha256:fcfe9390894efed11d24e6f74f6e9f1a"
                "893eeb731d46ced835501e0383ca9f2f"
            ),
            "issuer": "identity-provider",
            "key_id": "ASSERTION-GOLDEN-1",
            "subject": "operator:golden",
            "profile_id": "AOE-HQ-12",
            "audience": "sunderkey-runtime",
            "store_id": "STR-00112233445566778899AABBCCDDEEFF",
            "mission_id": "MISSION-GOLDEN-1",
            "operation": "sunderkey.mission.stop.v1",
            "operation_intent_sha256": (
                "sha256:440cce51589764536069145b6258260af"
                "e8d06c6c1f7bdac07e23ad450ccff51"
            ),
            "issued_at": "2030-01-02T03:06:00Z",
            "not_before": "2030-01-02T03:06:00Z",
            "expires_at": "2030-01-02T03:11:00Z",
            "signature": ZERO_SIGNATURE,
        }
        unsigned_assertion = PrincipalAssertion.from_dict(assertion_raw)
        assertion_signature = (
            "kazOBb0Nv6ntnffaFL1k7H-ucPINZtyNO4kCvZmNU9dCc_8bxku6SemCekEoHTsH"
            "AmrHvwhb95V-tklPe_k-AA"
        )
        self.assertEqual(
            hashlib.sha256(unsigned_assertion.signing_bytes()).hexdigest(),
            "eb60f4bb82137acddd0bc171520b8b73f7605cd974364902fc8bfe400024f81e",
        )
        self.assertEqual(
            b64url(assertion_private.sign(unsigned_assertion.signing_bytes())),
            assertion_signature,
        )
        assertion = replace(unsigned_assertion, signature=assertion_signature)
        self.assertEqual(
            assertion.content_sha256,
            "sha256:958e9be246f8d8e441ecd9bdf7671fd8d9ac557348650d96448625c7ed07f87e",
        )


class StrictIdentityLoaderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.factory = CredentialFactory()
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def write(self, name: str, content: bytes | str) -> Path:
        path = self.root / name
        if isinstance(content, str):
            path.write_text(content, encoding="utf-8", newline="\n")
        else:
            path.write_bytes(content)
        return path

    def test_all_strict_loaders_round_trip_signed_documents(self) -> None:
        policy = self.factory.policy()
        grant = self.factory.grant()
        assertion = self.factory.assertion(grant=grant)
        policy_path = self.write("policy.json", json.dumps(policy.to_dict()))
        grant_path = self.write("grant.json", json.dumps(grant.to_dict()))
        assertion_path = self.write("assertion.json", json.dumps(assertion.to_dict()))

        self.assertEqual(load_trust_policy(policy_path), policy)
        self.assertEqual(load_scope_grant(grant_path), grant)
        self.assertEqual(load_principal_assertion(assertion_path), assertion)

    def test_loader_rejects_nonregular_and_replaced_credential_file(self) -> None:
        policy_json = json.dumps(self.factory.policy().to_dict())
        source = self.write("source-policy.json", policy_json)
        replacement = self.write("other-policy.json", policy_json)
        with self.assertRaisesRegex(PrincipalAuthenticationError, "regular file"):
            load_trust_policy(self.root)
        with patch.object(
            Path,
            "stat",
            return_value=SimpleNamespace(st_mode=stat.S_IFIFO, st_size=0),
        ):
            with self.assertRaisesRegex(PrincipalAuthenticationError, "regular file"):
                load_trust_policy(source)

        original_open = identity_module.os.open
        observed_flags: list[int] = []

        def open_replacement(path, flags, *args, **kwargs):
            observed_flags.append(flags)
            if Path(path) == source:
                return original_open(replacement, flags, *args, **kwargs)
            return original_open(path, flags, *args, **kwargs)

        with patch.object(identity_module.os, "open", side_effect=open_replacement):
            with self.assertRaisesRegex(PrincipalAuthenticationError, "changed while opening"):
                load_trust_policy(source)
        if getattr(identity_module.os, "O_NONBLOCK", 0):
            self.assertTrue(observed_flags[0] & identity_module.os.O_NONBLOCK)

    def test_loader_bounds_growth_after_file_open(self) -> None:
        source = self.write("small.json", b"{}")
        original_fdopen = identity_module.os.fdopen

        def grow_before_read(descriptor, *args, **kwargs):
            with source.open("ab") as stream:
                stream.write(b"x" * 40)
            return original_fdopen(descriptor, *args, **kwargs)

        with patch.object(identity_module, "_MAX_CREDENTIAL_BYTES", 32):
            with patch.object(identity_module.os, "fdopen", side_effect=grow_before_read):
                with self.assertRaisesRegex(PrincipalAuthenticationError, "maximum size"):
                    identity_module._load_json_file(source, "credential")

    def test_duplicate_keys_are_rejected_at_any_depth(self) -> None:
        top_level = '{"schema_version":1,"schema_version":1}'
        nested = (
            '{"schema_version":1,"policy_id":"P","issuer":"I","audience":"A",'
            '"issued_at":"2026-07-30T09:00:00Z","not_before":"2026-07-30T09:00:00Z",'
            '"expires_at":"2026-07-30T12:00:00Z","max_scope_lifetime_seconds":1,'
            '"max_assertion_lifetime_seconds":1,"allowed_profiles":["AOE-HQ-12"],'
            '"allowed_subjects":["operator:alice"],'
            '"allowed_operations":["sunderkey.mission.stop.v1"],'
            '"keys":[{"key_id":"KEY","key_id":"OTHER"}],"root_key_id":"ROOT",'
            f'"signature":"{ZERO_SIGNATURE}"}}'
        )
        for index, content in enumerate((top_level, nested)):
            with (
                self.subTest(index=index),
                self.assertRaisesRegex(PrincipalAuthenticationError, "Duplicate"),
            ):
                load_trust_policy(self.write(f"duplicate-{index}.json", content))

    def test_bom_unknown_fields_and_floats_are_rejected(self) -> None:
        policy = self.factory.policy().to_dict()
        valid = json.dumps(policy).encode("utf-8")
        with self.assertRaisesRegex(PrincipalAuthenticationError, "BOM"):
            load_trust_policy(self.write("bom.json", b"\xef\xbb\xbf" + valid))

        unknown = dict(policy)
        unknown["extension"] = True
        with self.assertRaisesRegex(PrincipalAuthenticationError, "unknown fields"):
            load_trust_policy(self.write("unknown.json", json.dumps(unknown)))

        float_json = json.dumps(policy).replace(
            '"max_scope_lifetime_seconds": 3600',
            '"max_scope_lifetime_seconds": 1.5',
        )
        with self.assertRaisesRegex(PrincipalAuthenticationError, "Floating-point"):
            load_trust_policy(self.write("float.json", float_json))

    def test_bad_base64url_and_noncanonical_timestamps_are_rejected(self) -> None:
        grant = self.factory.grant().to_dict()
        for signature in ("***", ZERO_SIGNATURE + "=", "AA"):
            with self.subTest(signature=signature):
                candidate = dict(grant)
                candidate["signature"] = signature
                with self.assertRaisesRegex(PrincipalAuthenticationError, "base64url|64 bytes"):
                    load_scope_grant(
                        self.write(f"bad-{len(signature)}.json", json.dumps(candidate))
                    )

        assertion = self.factory.assertion().to_dict()
        assertion["issued_at"] = "2026-07-30T10:04:00+00:00"
        with self.assertRaisesRegex(PrincipalAuthenticationError, "canonical UTC"):
            load_principal_assertion(
                self.write("timestamp.json", json.dumps(assertion))
            )

    def test_unicode_and_unsorted_allowlists_are_rejected(self) -> None:
        policy = self.factory.policy().to_dict()
        policy["allowed_subjects"] = ["operator:\u00e1lice"]
        with self.assertRaisesRegex(PrincipalAuthenticationError, "ASCII"):
            load_trust_policy(self.write("unicode.json", json.dumps(policy)))

        policy = self.factory.policy().to_dict()
        policy["allowed_profiles"] = [PROFILE_ID, OTHER_PROFILE_ID]
        with self.assertRaisesRegex(PrincipalAuthenticationError, "ascending canonical order"):
            load_trust_policy(self.write("unsorted.json", json.dumps(policy)))

    def test_key_state_contract_is_strict(self) -> None:
        policy = self.factory.policy().to_dict()
        policy["keys"][0]["state"] = TrustKeyState.RETIRING.value
        policy["keys"][0]["retire_at"] = None
        with self.assertRaisesRegex(PrincipalAuthenticationError, "required for a retiring"):
            load_trust_policy(self.write("retiring.json", json.dumps(policy)))

        policy = self.factory.policy().to_dict()
        policy["keys"][0]["retire_at"] = "2026-07-30T10:00:00Z"
        with self.assertRaisesRegex(PrincipalAuthenticationError, "null for an active"):
            load_trust_policy(self.write("active.json", json.dumps(policy)))

    def test_replay_identifiers_and_key_material_separation_are_strict(self) -> None:
        grant = self.factory.grant().to_dict()
        grant["grant_id"] = "SGR-ABC"
        with self.assertRaisesRegex(PrincipalAuthenticationError, "32 uppercase"):
            load_scope_grant(self.write("grant-id.json", json.dumps(grant)))

        assertion = self.factory.assertion().to_dict()
        assertion["assertion_id"] = "PAS-" + "a" * 32
        with self.assertRaisesRegex(PrincipalAuthenticationError, "32 uppercase"):
            load_principal_assertion(
                self.write("assertion-id.json", json.dumps(assertion))
            )

        policy = self.factory.policy().to_dict()
        policy["keys"][1]["public_key"] = policy["keys"][0]["public_key"]
        with self.assertRaisesRegex(PrincipalAuthenticationError, "distinct Ed25519"):
            load_trust_policy(self.write("duplicate-key.json", json.dumps(policy)))

        policy = self.factory.policy().to_dict()
        policy["keys"][0]["key_id"] = ROOT_KEY_ID
        policy["keys"] = sorted(
            policy["keys"],
            key=lambda key: key["key_id"],
        )
        with self.assertRaisesRegex(
            PrincipalAuthenticationError,
            "root_key_id must not be reused",
        ):
            load_trust_policy(
                self.write("root-key-id.json", json.dumps(policy))
            )

    def test_loader_bounds_file_size_and_json_integers(self) -> None:
        oversized = b"{" + b" " * 1_048_576
        with self.assertRaisesRegex(
            PrincipalAuthenticationError,
            "maximum size",
        ):
            load_trust_policy(self.write("oversized.json", oversized))

        policy_json = json.dumps(self.factory.policy().to_dict())
        huge_integer = policy_json.replace(
            '"policy_version": 7',
            '"policy_version": ' + "9" * 10_000,
        )
        with self.assertRaisesRegex(
            PrincipalAuthenticationError,
            "signed 64-bit",
        ):
            load_trust_policy(
                self.write("huge-integer.json", huge_integer)
            )


if __name__ == "__main__":
    unittest.main()

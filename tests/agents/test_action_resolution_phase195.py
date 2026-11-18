"""Phase 195 typed action resolution and authenticated admission coverage."""

from __future__ import annotations

import copy
import inspect
import json
import re
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator, ValidationError

import sunderkey
import sunderkey.action_resolution as action_resolution
import sunderkey.authenticated_action_admission as durable_admission
from scripts.build_action_resolution import (
    authenticated_action_admission_schema,
    executable_action_resolution_schema,
)
from sunderkey.action_admission_contracts import (
    REQUIRED_EVIDENCE,
    ArtifactBinding,
    BudgetBinding,
    ContextBinding,
    CredentialLease,
    EvidenceObligation,
    HealthEvidence,
    HealthStatus,
    RestorationDuties,
    StopConditions,
    WorkerSession,
    evaluate_action_admission,
)
from sunderkey.action_resolution import (
    ActionResolutionError,
    ActionTier,
    AuthorizationRole,
    authenticate_action_admission,
    build_action_admission_revocation,
    build_action_authorization_quorum,
    build_action_parameter_set,
    build_executable_action_catalog,
    build_target_action_descriptor,
    parameter_contract_sha256,
    parse_action_parameter_set,
    parse_action_proposal_resolution,
    parse_authenticated_action_admission_receipt,
    reconstruct_action_admission_request,
    resolve_action_proposal,
    verify_authenticated_action_admission,
)
from sunderkey.authenticated_action_admission import (
    ActionAdmissionCommand,
    AuthenticatedActionAdmissionService,
    CurrentActionAdmissionMaterial,
    admission_authorization_intent_sha256,
    quorum_authorization_intent_sha256,
    resolution_authorization_intent_sha256,
    revocation_authorization_intent_sha256,
)
from sunderkey.errors import StoreError
from sunderkey.expert_review import (
    ExpertReviewClosureCertificate,
    ExpertReviewClosureRequest,
    ExpertReviewRecordSet,
    ExpertReviewSnapshot,
)
from sunderkey.qualification import _canonical_json
from sunderkey.types import ActionTier as MissionActionTier

ROOT = Path(__file__).resolve().parents[2]
FILES = (
    ROOT / "src/sunderkey/action_resolution.py",
    ROOT / "src/sunderkey/authenticated_action_admission.py",
    ROOT / "scripts/build_action_resolution.py",
    Path(__file__),
    ROOT / "registry/schemas/executable-action-resolution-v1.schema.json",
    ROOT / "registry/schemas/authenticated-action-admission-v1.schema.json",
)


def digest(character: str) -> str:
    return "sha256:" + character * 64


class CurrentReviewVerifier:
    def __init__(self, snapshot_id: str, closure_id: str) -> None:
        self.snapshot_id = snapshot_id
        self.closure_id = closure_id
        self.current = True
        self.calls = 0

    def verify_current(self, records, registry):  # type: ignore[no-untyped-def]
        del registry
        self.calls += 1
        if not self.current:
            raise ActionResolutionError("Authoritative closure is revoked")
        if (
            records.snapshot.snapshot_id != self.snapshot_id
            or records.closure.closure_id != self.closure_id
        ):
            raise ActionResolutionError("Authoritative closure identity differs")
        return action_resolution._seal_current_expert_review_closure(records)


class CurrentAuthorizationVerifier:
    def __init__(self) -> None:
        self.revoked_assertion_sha256s: set[str] = set()
        self.calls = 0

    def verify_current(self, authorization):  # type: ignore[no-untyped-def]
        self.calls += 1
        if authorization["assertion_sha256"] in self.revoked_assertion_sha256s:
            raise ActionResolutionError("Principal assertion is revoked")
        return action_resolution._seal_current_principal_authorization(authorization)


class ActionResolutionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.registry_sha256 = digest("a")
        snapshot_document = {
            "kind": "expert_review_snapshot",
            "snapshot_id": "ERS-" + "1" * 32,
            "snapshot_sha256": digest("1"),
            "tenant_id": "tenant:alpha",
            "mission_id": "mission:assessment-001",
            "plan_id": "plan:001",
            "target_scope_sha256": digest("b"),
            "authority_snapshot_sha256": digest("c"),
            "registry_sha256": self.registry_sha256,
            "products": [
                {
                    "work_id": "work:proposal-001",
                    "producer_profile_id": "AOE-GA-D01-S01",
                    "product_id": "EWP-" + "2" * 32,
                    "product_sha256": digest("2"),
                    "product_type": "action_proposal",
                }
            ],
        }
        closure_document = {
            "kind": "expert_review_closure_certificate",
            "closure_id": "ERC-" + "3" * 32,
            "closure_sha256": digest("3"),
            "snapshot_id": snapshot_document["snapshot_id"],
            "snapshot_sha256": snapshot_document["snapshot_sha256"],
            "disposition": "accepted",
        }
        self.records = ExpertReviewRecordSet(
            snapshot=ExpertReviewSnapshot(_canonical_json(snapshot_document)),
            receipts=(),
            closure_request=ExpertReviewClosureRequest(_canonical_json({"request": "test"})),
            closure=ExpertReviewClosureCertificate(_canonical_json(closure_document)),
        )
        self.registry = object()
        self.verifier = CurrentReviewVerifier(
            snapshot_document["snapshot_id"], closure_document["closure_id"]
        )
        contract = [
            {"name": "allow_redirect", "required": True, "value_type": "boolean"},
            {"name": "attempt_count", "required": True, "value_type": "integer"},
            {"name": "method", "required": True, "value_type": "identifier"},
            {"name": "path", "required": True, "value_type": "string"},
            {"name": "required_headers", "required": False, "value_type": "string_array"},
        ]
        self.entry = {
            "action_type": "api.request",
            "executor_supported": True,
            "maximum_action_tier": "R4",
            "parameter_contract": contract,
            "parameter_contract_sha256": parameter_contract_sha256(contract),
            "r4_executor_supported": True,
            "supported_environments": ["live", "replica", "sandbox"],
            "tool_artifact_ref": "artifact:api-executor",
            "tool_artifact_sha256": digest("d"),
            "tool_exact_version": "2.1.0",
        }
        self.catalog = build_executable_action_catalog(
            catalog_name="catalog:production-actions",
            catalog_version="1.0.0",
            registry_sha256=self.registry_sha256,
            entries=[self.entry],
        )
        self.parameters = build_action_parameter_set(
            self.catalog,
            action_type="api.request",
            parameters={
                "allow_redirect": False,
                "attempt_count": 1,
                "method": "GET",
                "path": "/health",
                "required_headers": ["accept", "x-request-id"],
            },
        )
        self.target = build_target_action_descriptor(
            tenant_id="tenant:alpha",
            mission_id="mission:assessment-001",
            target_scope_sha256=digest("b"),
            authority_snapshot_sha256=digest("c"),
            target_id="target:api-001",
            target_sha256=digest("e"),
            environment="live",
        )
        self.verify_patch = patch.object(
            action_resolution,
            "verify_expert_review_record_set",
            side_effect=lambda records, registry: records,
        )
        self.verify_patch.start()
        self.addCleanup(self.verify_patch.stop)
        self.resolution = self.resolve(ActionTier.R3)
        self.authorization_verifier = CurrentAuthorizationVerifier()
        self.quorum = build_action_authorization_quorum(
            self.resolution,
            self.authorization_verifier,
            approvals=[
                self.authorization(AuthorizationRole.MISSION_OWNER, "operator:owner", "f"),
                self.authorization(
                    AuthorizationRole.INDEPENDENT_CONTROL, "AOE-HQ-14", "0"
                ),
            ],
            approved_at="2026-09-20T12:00:00Z",
            expires_at="2026-09-20T13:00:00Z",
        )
        self.request = self.admission_request()
        decision = evaluate_action_admission(
            self.request, evaluated_at="2026-09-20T12:05:00Z"
        )
        resolution_document = self.resolution.to_dict()
        self.receipt = parse_authenticated_action_admission_receipt(
            action_resolution._address_record(
                "authenticated_action_admission_receipt",
                {
                    "schema_version": 1,
                    "kind": "authenticated_action_admission_receipt",
                    "resolution_id": self.resolution.resolution_id,
                    "resolution_sha256": self.resolution.resolution_sha256,
                    "quorum_id": self.quorum.quorum_id,
                    "quorum_sha256": self.quorum.quorum_sha256,
                    "request_id": self.request.request_id,
                    "request_sha256": self.request.request_sha256,
                    "decision_id": decision.decision_id,
                    "decision_sha256": decision.decision_sha256,
                    "tenant_id": resolution_document["tenant_id"],
                    "mission_id": resolution_document["mission_id"],
                    "scope_sha256": resolution_document["target_scope_sha256"],
                    "target_sha256": resolution_document["target_sha256"],
                    "action_sha256": resolution_document["action_sha256"],
                    "action_tier": resolution_document["action_tier"],
                    "evaluated_at": "2026-09-20T12:05:00Z",
                    "status": "admitted_contract_only",
                    "admission_authorization": self.authorization(
                        AuthorizationRole.ADMISSION_CONTROL,
                        "service:admission",
                        "4",
                    ),
                    "identity_assurance": "mission_store_principal_assertion",
                    "effects": dict(action_resolution.NO_EFFECTS),
                },
            )
        )

    def resolve(self, tier: ActionTier):
        return resolve_action_proposal(
            self.records,
            self.registry,  # type: ignore[arg-type]
            self.verifier,
            self.catalog,
            self.parameters,
            self.target,
            proposal_product_id="EWP-" + "2" * 32,
            action_type="api.request",
            action_tier=tier,
            idempotency_key_sha256=digest("9"),
            resolver_profile_id="AOE-HQ-19",
            resolver_subject="resolver:typed-001",
            resolved_at="2026-09-20T11:55:00Z",
        )

    def authorization(
        self,
        role: AuthorizationRole,
        profile_id: str,
        character: str,
        *,
        resolution=None,
        tier: str = "R4",
    ) -> dict[str, object]:
        resolution = resolution or self.resolution
        document = resolution.to_dict()
        return {
            "role": role.value,
            "principal_profile_id": profile_id,
            "principal_subject": f"subject:{profile_id}",
            "assertion_issuer": f"issuer:{character}",
            "assertion_id": f"assertion:{character}",
            "assertion_sha256": digest(character),
            "assertion_key_sha256": digest("a"),
            "trust_policy_sha256": digest("5"),
            "scope_grant_sha256": digest("6"),
            "operation_intent_sha256": digest("7"),
            "canonical_replay_key_sha256": digest(character),
            "tenant_id": document["tenant_id"],
            "mission_id": document["mission_id"],
            "scope_sha256": document["target_scope_sha256"],
            "target_sha256": document["target_sha256"],
            "action_sha256": document["action_sha256"],
            "resolution_sha256": resolution.resolution_sha256,
            "authorized_tier": tier,
            "decision": "approved",
            "issued_at": "2026-09-20T11:00:00Z",
            "expires_at": "2026-09-20T13:00:00Z",
        }

    def admission_request(self):
        document = self.resolution.to_dict()
        tenant = document["tenant_id"]
        mission = document["mission_id"]
        scope = document["target_scope_sha256"]
        target_sha256 = document["target_sha256"]
        action_sha256 = document["action_sha256"]
        worker = WorkerSession(
            worker_id="worker:api-017",
            worker_profile_id="AOE-GA-D01-S01",
            session_id="session:lease-004",
            tenant_id=tenant,
            mission_id=mission,
            fence_token_sha256=digest("8"),
            leader_epoch=7,
            issued_at="2026-09-20T11:00:00Z",
            expires_at="2026-09-20T13:00:00Z",
        )
        evidence = tuple(
            EvidenceObligation(
                evidence_kind=kind,
                evidence_sha256=digest(str(index + 1)),
                tenant_id=tenant,
                mission_id=mission,
                scope_sha256=scope,
                target_sha256=target_sha256,
                action_sha256=action_sha256,
                producer_id=f"producer:{kind.value}",
                issued_at="2026-09-20T11:00:00Z",
                expires_at="2026-09-20T13:00:00Z",
            )
            for index, kind in enumerate(sorted(REQUIRED_EVIDENCE, key=lambda item: item.value))
        )
        return reconstruct_action_admission_request(
            self.resolution,
            self.quorum,
            context=ContextBinding(
                tenant_id=tenant,
                mission_id=mission,
                scope_id="scope:approved-001",
                scope_sha256=scope,
                policy=ArtifactBinding("artifact:admission-policy", digest("a"), "1.0.0"),
            ),
            worker_session=worker,
            credential_lease=CredentialLease(
                lease_id="credential-lease:001",
                credential_ref_sha256=digest("b"),
                tenant_id=tenant,
                mission_id=mission,
                scope_sha256=scope,
                worker_id=worker.worker_id,
                session_id=worker.session_id,
                fence_token_sha256=worker.fence_token_sha256,
                leader_epoch=worker.leader_epoch,
                permitted_action_sha256=action_sha256,
                revoked=False,
                issued_at="2026-09-20T11:00:00Z",
                expires_at="2026-09-20T13:00:00Z",
            ),
            health=HealthEvidence(
                worker_id=worker.worker_id,
                session_id=worker.session_id,
                fence_token_sha256=worker.fence_token_sha256,
                leader_epoch=worker.leader_epoch,
                status=HealthStatus.HEALTHY,
                evidence_sha256=digest("c"),
                observed_at="2026-09-20T12:00:00Z",
                expires_at="2026-09-20T12:30:00Z",
            ),
            budget=BudgetBinding(
                tenant_id=tenant,
                mission_id=mission,
                budget_sha256=digest("d"),
                request_limit=10,
                requests_used=0,
                token_limit=100,
                tokens_used=0,
                cost_limit_microunits=100,
                cost_used_microunits=0,
                action_request_cost=1,
                action_token_cost=1,
                action_cost_microunits=1,
            ),
            evidence_obligations=evidence,
            stop_conditions=StopConditions(
                stop_contract_sha256=digest("e"),
                monitor_session_id="session:monitor-009",
                monitor_worker_id="worker:safety-003",
                scope_sha256=scope,
                target_sha256=target_sha256,
                action_sha256=action_sha256,
                maximum_impact_events=1,
                stop_deadline_at="2026-09-20T12:45:00Z",
                expires_at="2026-09-20T12:30:00Z",
            ),
            restoration_duties=RestorationDuties(
                required=True,
                restoration_plan_sha256=digest("f"),
                owner_profile_id="AOE-HQ-14",
                verifier_profile_id="AOE-HQ-20",
                scope_sha256=scope,
                target_sha256=target_sha256,
                action_sha256=action_sha256,
                completion_evidence_required=True,
            ),
            requested_at="2026-09-20T12:00:00Z",
            expires_at="2026-09-20T12:30:00Z",
        )

    def test_full_chain_is_content_addressed_contract_only_and_active(self) -> None:
        with self.assertRaisesRegex(ActionResolutionError, "Portable verification"):
            verify_authenticated_action_admission(
                self.resolution,
                self.quorum,
                self.request,
                self.receipt,
                self.records,
                self.registry,  # type: ignore[arg-type]
                self.verifier,
                self.authorization_verifier,
            )
        self.assertEqual(self.request.action.action_type, "api.request")
        self.assertEqual(self.request.action.action_tier.value, "R3")
        self.assertEqual(self.request.target.target_id, "target:api-001")
        self.assertEqual(self.receipt.to_dict()["effects"], dict(action_resolution.NO_EFFECTS))
        self.assertGreaterEqual(self.verifier.calls, 1)

    def test_revocation_invalidates_the_receipt(self) -> None:
        with self.assertRaisesRegex(ActionResolutionError, "Portable revocation"):
            build_action_admission_revocation(
                self.receipt,
                self.authorization_verifier,
                reason_code="authority:withdrawn",
                control_authorization=self.authorization(
                    AuthorizationRole.INDEPENDENT_CONTROL, "AOE-HQ-20", "3"
                ),
                revoked_at="2026-09-20T12:10:00Z",
            )

    def test_current_authoritative_closure_is_required_twice(self) -> None:
        with self.assertRaisesRegex(ActionResolutionError, "point-of-use"):
            resolve_action_proposal(
                self.records,
                self.registry,  # type: ignore[arg-type]
                object(),  # type: ignore[arg-type]
                self.catalog,
                self.parameters,
                self.target,
                proposal_product_id="EWP-" + "2" * 32,
                action_type="api.request",
                action_tier="R3",
                idempotency_key_sha256=digest("9"),
                resolver_profile_id="AOE-HQ-19",
                resolver_subject="resolver:typed-001",
                resolved_at="2026-09-20T11:55:00Z",
            )
        self.verifier.current = False
        with self.assertRaisesRegex(ActionResolutionError, "Portable admission"):
            authenticate_action_admission(
                self.resolution,
                self.quorum,
                self.request,
                self.records,
                self.registry,  # type: ignore[arg-type]
                self.verifier,
                self.authorization_verifier,
                evaluated_at="2026-09-20T12:05:00Z",
                admission_authorization=self.authorization(
                    AuthorizationRole.ADMISSION_CONTROL, "service:new", "2"
                ),
            )

    def test_current_principal_assertions_are_required_at_point_of_use(self) -> None:
        with self.assertRaisesRegex(ActionResolutionError, "point-of-use"):
            build_action_authorization_quorum(
                self.resolution,
                object(),  # type: ignore[arg-type]
                approvals=[
                    self.authorization(AuthorizationRole.MISSION_OWNER, "operator:owner", "f"),
                    self.authorization(
                        AuthorizationRole.INDEPENDENT_CONTROL, "AOE-HQ-14", "0"
                    ),
                ],
                approved_at="2026-09-20T12:00:00Z",
                expires_at="2026-09-20T13:00:00Z",
            )
        self.authorization_verifier.revoked_assertion_sha256s.add(digest("4"))
        with self.assertRaisesRegex(ActionResolutionError, "Portable verification"):
            verify_authenticated_action_admission(
                self.resolution,
                self.quorum,
                self.request,
                self.receipt,
                self.records,
                self.registry,  # type: ignore[arg-type]
                self.verifier,
                self.authorization_verifier,
            )

    def test_resolution_uses_typed_inputs_not_model_prose(self) -> None:
        source = (ROOT / "src/sunderkey/action_resolution.py").read_text(encoding="utf-8")
        self.assertNotIn("proposed_" + "actions", source)
        self.assertEqual(
            set(self.parameters.to_dict()["parameters"]),
            {"allow_redirect", "attempt_count", "method", "path", "required_headers"},
        )

    def test_parameter_coercion_unknowns_and_moving_versions_fail_closed(self) -> None:
        raw = self.parameters.to_dict()
        raw["parameters"]["attempt_count"] = True
        raw = action_resolution._address_record(
            "action_parameter_set",
            {
                key: value
                for key, value in raw.items()
                if key not in {"parameter_set_id", "parameter_set_sha256"}
            },
        )
        with self.assertRaisesRegex(ActionResolutionError, "invalid"):
            parse_action_parameter_set(raw, self.catalog)
        raw = self.parameters.to_dict()
        raw["parameters"]["unknown"] = "value"
        raw = action_resolution._address_record(
            "action_parameter_set",
            {
                key: value
                for key, value in raw.items()
                if key not in {"parameter_set_id", "parameter_set_sha256"}
            },
        )
        with self.assertRaisesRegex(ActionResolutionError, "names"):
            parse_action_parameter_set(raw, self.catalog)
        entry = copy.deepcopy(self.entry)
        entry["tool_exact_version"] = "latest"
        with self.assertRaisesRegex(ActionResolutionError, "nonmoving"):
            build_executable_action_catalog(
                catalog_name="catalog:test",
                catalog_version="1.0.0",
                registry_sha256=self.registry_sha256,
                entries=[entry],
            )
        for value in ("line\nfeed", "tab\tvalue", "return\rvalue", "delete\x7fvalue"):
            with self.subTest(value=repr(value)):
                raw = self.parameters.to_dict()
                raw["parameters"]["path"] = value
                raw = action_resolution._address_record(
                    "action_parameter_set",
                    {
                        key: item
                        for key, item in raw.items()
                        if key not in {"parameter_set_id", "parameter_set_sha256"}
                    },
                )
                with self.assertRaisesRegex(ActionResolutionError, "exact string"):
                    parse_action_parameter_set(raw, self.catalog)

    def test_r5_is_rejected_and_r4_requires_explicit_executor_support(self) -> None:
        with self.assertRaisesRegex(ActionResolutionError, "R5"):
            self.resolve(ActionTier.R5)
        entry = copy.deepcopy(self.entry)
        entry["r4_executor_supported"] = False
        catalog = build_executable_action_catalog(
            catalog_name="catalog:no-r4",
            catalog_version="1.0.0",
            registry_sha256=self.registry_sha256,
            entries=[entry],
        )
        parameters = build_action_parameter_set(
            catalog,
            action_type="api.request",
            parameters={
                "allow_redirect": False,
                "attempt_count": 1,
                "method": "GET",
                "path": "/health",
            },
        )
        with self.assertRaisesRegex(ActionResolutionError, "R4"):
            resolve_action_proposal(
                self.records,
                self.registry,  # type: ignore[arg-type]
                self.verifier,
                catalog,
                parameters,
                self.target,
                proposal_product_id="EWP-" + "2" * 32,
                action_type="api.request",
                action_tier="R4",
                idempotency_key_sha256=digest("9"),
                resolver_profile_id="AOE-HQ-19",
                resolver_subject="resolver:typed-001",
                resolved_at="2026-09-20T11:55:00Z",
            )

    def test_r3_requires_control_and_replay_is_rejected(self) -> None:
        portable_only = parse_action_proposal_resolution(self.resolution.to_dict())
        with self.assertRaisesRegex(ActionResolutionError, "proof-sealed"):
            build_action_authorization_quorum(
                portable_only,
                self.authorization_verifier,
                approvals=[
                    self.authorization(AuthorizationRole.MISSION_OWNER, "operator:owner", "f"),
                    self.authorization(
                        AuthorizationRole.INDEPENDENT_CONTROL, "AOE-HQ-14", "0"
                    ),
                ],
                approved_at="2026-09-20T12:00:00Z",
                expires_at="2026-09-20T13:00:00Z",
            )
        with self.assertRaisesRegex(ActionResolutionError, "roles"):
            build_action_authorization_quorum(
                self.resolution,
                self.authorization_verifier,
                approvals=[
                    self.authorization(AuthorizationRole.MISSION_OWNER, "operator:owner", "f")
                ],
                approved_at="2026-09-20T12:00:00Z",
                expires_at="2026-09-20T13:00:00Z",
            )
        owner = self.authorization(AuthorizationRole.MISSION_OWNER, "operator:owner", "f")
        control = self.authorization(
            AuthorizationRole.INDEPENDENT_CONTROL, "AOE-HQ-14", "0"
        )
        control["canonical_replay_key_sha256"] = owner["canonical_replay_key_sha256"]
        with self.assertRaisesRegex(ActionResolutionError, "reuses"):
            build_action_authorization_quorum(
                self.resolution,
                self.authorization_verifier,
                approvals=[owner, control],
                approved_at="2026-09-20T12:00:00Z",
                expires_at="2026-09-20T13:00:00Z",
            )

    def test_scope_lineage_tamper_and_resolution_content_tamper_fail(self) -> None:
        wrong_target = build_target_action_descriptor(
            tenant_id="tenant:alpha",
            mission_id="mission:assessment-001",
            target_scope_sha256=digest("0"),
            authority_snapshot_sha256=digest("c"),
            target_id="target:api-001",
            target_sha256=digest("e"),
            environment="live",
        )
        with self.assertRaisesRegex(ActionResolutionError, "reviewed proposal scope"):
            resolve_action_proposal(
                self.records,
                self.registry,  # type: ignore[arg-type]
                self.verifier,
                self.catalog,
                self.parameters,
                wrong_target,
                proposal_product_id="EWP-" + "2" * 32,
                action_type="api.request",
                action_tier="R3",
                idempotency_key_sha256=digest("9"),
                resolver_profile_id="AOE-HQ-19",
                resolver_subject="resolver:typed-001",
                resolved_at="2026-09-20T11:55:00Z",
            )
        raw = self.resolution.to_dict()
        raw["proposal_product_sha256"] = digest("8")
        with self.assertRaisesRegex(ActionResolutionError, "content address"):
            parse_action_proposal_resolution(raw)

    def test_receipt_tamper_unknown_fields_and_authentication_reuse_fail(self) -> None:
        raw = self.receipt.to_dict()
        raw["target_sha256"] = digest("0")
        with self.assertRaisesRegex(ActionResolutionError, "binding|content address"):
            parse_authenticated_action_admission_receipt(raw)
        raw = self.receipt.to_dict()
        raw["unknown"] = True
        with self.assertRaisesRegex(ActionResolutionError, "fields"):
            parse_authenticated_action_admission_receipt(raw)
        reused = self.quorum.to_dict()["approvals"][0].copy()
        reused["role"] = AuthorizationRole.ADMISSION_CONTROL.value
        reused["principal_profile_id"] = "service:admission-replay"
        reused["principal_subject"] = "subject:admission-replay"
        reused["assertion_issuer"] = "issuer:admission-replay"
        reused["assertion_id"] = "assertion:admission-replay"
        with self.assertRaisesRegex(ActionResolutionError, "Portable admission"):
            authenticate_action_admission(
                self.resolution,
                self.quorum,
                self.request,
                self.records,
                self.registry,  # type: ignore[arg-type]
                self.verifier,
                self.authorization_verifier,
                evaluated_at="2026-09-20T12:05:00Z",
                admission_authorization=reused,
            )

    def test_closed_checked_schemas_validate_each_record_family(self) -> None:
        resolution_schema = executable_action_resolution_schema()
        admission_schema = authenticated_action_admission_schema()
        self.assertEqual(
            json.loads(
                (ROOT / "registry/schemas/executable-action-resolution-v1.schema.json").read_text(
                    encoding="utf-8"
                )
            ),
            resolution_schema,
        )
        self.assertEqual(
            json.loads(
                (ROOT / "registry/schemas/authenticated-action-admission-v1.schema.json").read_text(
                    encoding="utf-8"
                )
            ),
            admission_schema,
        )
        Draft202012Validator.check_schema(resolution_schema)
        Draft202012Validator.check_schema(admission_schema)
        def assert_no_untyped_schema(node):  # type: ignore[no-untyped-def]
            if isinstance(node, dict):
                self.assertNotEqual(node, {})
                for item in node.values():
                    assert_no_untyped_schema(item)
            elif isinstance(node, list):
                for item in node:
                    assert_no_untyped_schema(item)

        assert_no_untyped_schema(resolution_schema)
        assert_no_untyped_schema(admission_schema)
        resolution_validator = Draft202012Validator(resolution_schema)
        admission_validator = Draft202012Validator(admission_schema)
        for record in (self.catalog, self.parameters, self.target, self.resolution):
            resolution_validator.validate(record.to_dict())
        for record in (self.quorum, self.receipt):
            admission_validator.validate(record.to_dict())
        unknown = self.resolution.to_dict()
        unknown["unknown"] = True
        with self.assertRaises(ValidationError):
            resolution_validator.validate(unknown)
        nested_unknown = self.quorum.to_dict()
        nested_unknown["approvals"][0]["unknown"] = True
        with self.assertRaises(ValidationError):
            admission_validator.validate(nested_unknown)
        wrong_role_type = self.quorum.to_dict()
        wrong_role_type["approvals"][0]["role"] = 7
        with self.assertRaises(ValidationError):
            admission_validator.validate(wrong_role_type)
        wrong_effect = self.resolution.to_dict()
        wrong_effect["effects"]["network_call_performed"] = "false"
        with self.assertRaises(ValidationError):
            resolution_validator.validate(wrong_effect)
        moving_version = self.catalog.to_dict()
        moving_version["catalog_version"] = "LATEST"
        with self.assertRaises(ValidationError):
            resolution_validator.validate(moving_version)

    def test_public_contract_does_not_expand_mission_r5_execution(self) -> None:
        self.assertIs(sunderkey.ExecutableActionCatalog, action_resolution.ExecutableActionCatalog)
        self.assertIs(
            sunderkey.AuthenticatedActionAdmissionReceipt,
            action_resolution.AuthenticatedActionAdmissionReceipt,
        )
        self.assertEqual(MissionActionTier.R5.value, "R5")
        self.assertNotIn("R5", {item.value for item in action_resolution.LegacyActionTier})

    def test_runtime_and_schema_both_reject_r5_catalog_and_authorization(self) -> None:
        entry = {**self.entry, "maximum_action_tier": "R5"}
        with self.assertRaisesRegex(ActionResolutionError, "R5"):
            build_executable_action_catalog(
                catalog_name="catalog:r5-rejected",
                catalog_version="1.0.0",
                registry_sha256=self.registry_sha256,
                entries=[entry],
            )
        authorization = self.authorization(
            AuthorizationRole.MISSION_OWNER,
            "operator:owner",
            "f",
            tier="R5",
        )
        with self.assertRaisesRegex(ActionResolutionError, "R5"):
            action_resolution._authorization(authorization, "authorization")
        schema = executable_action_resolution_schema()
        entries = next(
            variant["properties"]["entries"]
            for variant in schema["oneOf"]
            if variant["properties"]["kind"].get("const")
            == "executable_action_catalog"
        )
        self.assertEqual(entries["minItems"], 1)

    def test_no_markers_unicode_dashes_or_runtime_clients(self) -> None:
        marker_parts = (
            "generated " + "by",
            "written " + "by (?:an )?ai",
            "as an " + "ai",
            "chat" + "gpt",
            "co" + "dex",
            "clau" + "de",
            "gem" + "ini",
            "co-authored-" + "by",
        )
        marker = re.compile("|".join(marker_parts), re.IGNORECASE)
        for path in FILES:
            content = path.read_text(encoding="utf-8")
            self.assertNotRegex(content, marker)
            self.assertNotIn("\u2013", content)
            self.assertNotIn("\u2014", content)
        source = FILES[0].read_text(encoding="utf-8")
        for forbidden in ("import requests", "import socket", "subprocess", "urllib.request"):
            self.assertNotIn(forbidden, source)


class OwnedAdmissionAuthority:
    """State-backed test adapter installed once in its owning service."""

    def __init__(self, material: CurrentActionAdmissionMaterial) -> None:
        self.material = material
        self.revoked = False
        self.rotated = False
        self.fail_admission = False
        self.reuse_admission_for_revocation = False
        self.current_checks = 0
        self.last_resolution = None
        self.last_quorum = None
        self.last_request = None

    @staticmethod
    def _require_transaction(connection: sqlite3.Connection) -> None:
        if not connection.in_transaction:
            raise AssertionError("authority check was outside the locked transaction")

    def _authorization(
        self,
        resolution,
        role: AuthorizationRole,
        profile_id: str,
        character: str,
        operation_intent_sha256: str,
    ) -> dict[str, object]:
        document = resolution.to_dict()
        subject = (
            self.material.resolver_subject
            if role is AuthorizationRole.TYPED_RESOLVER
            else f"subject:{profile_id}"
        )
        return {
            "role": role.value,
            "principal_profile_id": profile_id,
            "principal_subject": subject,
            "assertion_issuer": f"issuer:{character}",
            "assertion_id": f"assertion:{character}",
            "assertion_sha256": digest(character),
            "assertion_key_sha256": digest("a"),
            "trust_policy_sha256": digest("5"),
            "scope_grant_sha256": digest("6"),
            "operation_intent_sha256": operation_intent_sha256,
            "canonical_replay_key_sha256": digest(character),
            "tenant_id": document["tenant_id"],
            "mission_id": document["mission_id"],
            "scope_sha256": document["target_scope_sha256"],
            "target_sha256": document["target_sha256"],
            "action_sha256": document["action_sha256"],
            "resolution_sha256": resolution.resolution_sha256,
            "authorized_tier": "R4",
            "decision": "approved",
            "issued_at": "2026-09-20T11:00:00Z",
            "expires_at": "2026-09-20T13:00:00Z",
        }

    def load_current_material(self, connection, command, evaluated_at):  # type: ignore[no-untyped-def]
        del command, evaluated_at
        self._require_transaction(connection)
        if self.revoked:
            raise ActionResolutionError("Authoritative review state is revoked")
        return self.material

    def authorize_resolution(
        self, connection, resolution, operation_intent_sha256, evaluated_at
    ):  # type: ignore[no-untyped-def]
        del evaluated_at
        self._require_transaction(connection)
        self.last_resolution = resolution
        self.assertEqualIntent(
            operation_intent_sha256,
            resolution_authorization_intent_sha256(resolution),
        )
        return self._authorization(
            resolution,
            AuthorizationRole.TYPED_RESOLVER,
            self.material.resolver_profile_id,
            "1",
            operation_intent_sha256,
        )

    def authorize_quorum(
        self, connection, resolution, operation_intents, evaluated_at
    ):  # type: ignore[no-untyped-def]
        del evaluated_at
        self._require_transaction(connection)
        roles = [AuthorizationRole.MISSION_OWNER]
        if resolution.to_dict()["action_tier"] in {"R3", "R4"}:
            roles.append(AuthorizationRole.INDEPENDENT_CONTROL)
        profiles = {
            AuthorizationRole.MISSION_OWNER: ("operator:owner", "2"),
            AuthorizationRole.INDEPENDENT_CONTROL: ("AOE-HQ-14", "3"),
        }
        result = []
        for role in roles:
            self.assertEqualIntent(
                operation_intents[role],
                quorum_authorization_intent_sha256(
                    resolution,
                    role,
                    approved_at=self.material.approved_at,
                    expires_at=self.material.quorum_expires_at,
                ),
            )
            profile, character = profiles[role]
            result.append(
                self._authorization(
                    resolution,
                    role,
                    profile,
                    character,
                    operation_intents[role],
                )
            )
        return result

    def authorize_admission(
        self,
        connection,
        resolution,
        quorum,
        request,
        operation_intent_sha256,
        evaluated_at,
    ):  # type: ignore[no-untyped-def]
        del evaluated_at
        self._require_transaction(connection)
        if self.fail_admission:
            raise ActionResolutionError("Injected admission authorization failure")
        self.last_quorum = quorum
        self.last_request = request
        self.assertEqualIntent(
            operation_intent_sha256,
            admission_authorization_intent_sha256(resolution, quorum, request),
        )
        return self._authorization(
            resolution,
            AuthorizationRole.ADMISSION_CONTROL,
            "service:admission",
            "4",
            operation_intent_sha256,
        )

    def verify_stored_current(
        self, connection, stored, evaluated_at
    ):  # type: ignore[no-untyped-def]
        del evaluated_at
        self._require_transaction(connection)
        self.current_checks += 1
        if self.revoked:
            raise ActionResolutionError("Authoritative review state is revoked")
        if self.rotated:
            return durable_admission.CurrentActionAuthorityState(
                **{
                    **stored.authority_state.to_dict(),
                    "authority_revision_sha256": digest("0"),
                }
            )
        return stored.authority_state

    def authorize_revocation(
        self,
        connection,
        stored,
        reason_code,
        operation_intent_sha256,
        revoked_at,
    ):  # type: ignore[no-untyped-def]
        self._require_transaction(connection)
        self.assertEqualIntent(
            operation_intent_sha256,
            revocation_authorization_intent_sha256(
                stored.receipt,
                reason_code=reason_code,
                revoked_at=revoked_at,
            ),
        )
        character = "4" if self.reuse_admission_for_revocation else "7"
        profile = "service:admission" if self.reuse_admission_for_revocation else "AOE-HQ-20"
        return self._authorization(
            stored.resolution,
            AuthorizationRole.INDEPENDENT_CONTROL,
            profile,
            character,
            operation_intent_sha256,
        )

    @staticmethod
    def assertEqualIntent(actual: str, expected: str) -> None:
        if actual != expected:
            raise AssertionError("service supplied the wrong authorization intent")


class DurableActionAdmissionTests(ActionResolutionTests):
    def setUp(self) -> None:
        super().setUp()
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        request = self.request
        self.material = CurrentActionAdmissionMaterial(
            records=self.records,
            registry=self.registry,  # type: ignore[arg-type]
            catalog=self.catalog,
            parameters=self.parameters,
            target=self.target,
            resolver_profile_id="AOE-HQ-19",
            resolver_subject="resolver:typed-001",
            context=request.context,
            worker_session=request.worker_session,
            credential_lease=request.credential_lease,
            health=request.health,
            budget=request.budget,
            evidence_obligations=request.evidence_obligations,
            stop_conditions=request.stop_conditions,
            restoration_duties=request.restoration_duties,
            resolved_at="2026-09-20T11:55:00Z",
            approved_at="2026-09-20T12:00:00Z",
            quorum_expires_at="2026-09-20T13:00:00Z",
            requested_at="2026-09-20T12:00:00Z",
            expires_at="2026-09-20T12:30:00Z",
            catalog_authority_sha256=digest("8"),
            authority_revision_sha256=digest("9"),
        )
        self.authority = OwnedAdmissionAuthority(self.material)
        self.database = Path(self.temporary.name) / "admission.sqlite3"
        self.service = AuthenticatedActionAdmissionService(
            self.database,
            self.authority,
            self.verifier,
            self.material.registry,
            clock=lambda: datetime(2026, 9, 20, 12, 5, tzinfo=UTC),
        )
        self.service.initialize()
        self.command = ActionAdmissionCommand(
            tenant_id="tenant:alpha",
            mission_id="mission:assessment-001",
            proposal_product_id="EWP-" + "2" * 32,
            action_type="api.request",
            action_tier=ActionTier.R3,
            idempotency_key_sha256=digest("9"),
        )

    def _counts(self) -> tuple[int, int, int, int]:
        connection = sqlite3.connect(self.database)
        try:
            return tuple(
                int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
                for table in (
                    "action_admission_receipts",
                    "action_admission_assertion_uses",
                    "action_admission_budget_reservations",
                    "action_admission_revocations",
                )
            )  # type: ignore[return-value]
        finally:
            connection.close()

    def test_service_reconstructs_and_persists_the_exact_request(self) -> None:
        receipt = self.service.admit(self.command)
        self.assertIsNotNone(self.authority.last_request)
        admitted = self.authority.last_request
        self.assertEqual(admitted.context, self.material.context)
        self.assertEqual(admitted.worker_session, self.material.worker_session)
        self.assertEqual(admitted.credential_lease, self.material.credential_lease)
        self.assertEqual(admitted.health, self.material.health)
        self.assertEqual(admitted.budget, self.material.budget)
        self.assertEqual(admitted.evidence_obligations, self.material.evidence_obligations)
        self.assertEqual(admitted.stop_conditions, self.material.stop_conditions)
        self.assertEqual(admitted.restoration_duties, self.material.restoration_duties)
        self.assertEqual(admitted.action.to_dict(), self.request.action.to_dict())
        self.assertEqual(admitted.target.to_dict(), self.request.target.to_dict())
        self.assertEqual(admitted.requested_at, self.material.requested_at)
        self.assertEqual(admitted.expires_at, self.material.expires_at)
        self.assertEqual(self._counts(), (1, 4, 1, 0))
        proof = self.service.verify_current(receipt.receipt_id)
        self.service.require_owned_current_proof(proof)
        self.assertEqual(proof.receipt.to_dict(), receipt.to_dict())
        self.assertNotIn("request", inspect.signature(self.service.admit).parameters)

    def test_restart_exact_replay_returns_identical_receipt(self) -> None:
        first = self.service.admit(self.command)
        restarted = AuthenticatedActionAdmissionService(
            self.database,
            self.authority,
            self.verifier,
            self.material.registry,
            clock=lambda: datetime(2026, 9, 20, 12, 6, tzinfo=UTC),
        )
        second = restarted.admit(self.command)
        self.assertEqual(first.document_json, second.document_json)
        self.assertEqual(self._counts(), (1, 4, 1, 0))
        self.assertGreaterEqual(self.authority.current_checks, 1)

    def test_review_authority_is_rechecked_on_every_durable_operation(self) -> None:
        receipt = self.service.admit(self.command)
        after_admit = self.verifier.calls
        self.service.admit(self.command)
        self.assertEqual(self.verifier.calls, after_admit + 1)
        self.service.verify_current(receipt.receipt_id)
        self.assertEqual(self.verifier.calls, after_admit + 2)
        self.service.revoke(
            receipt.receipt_id,
            reason_code="authority:withdrawn",
            revoked_at="2026-09-20T12:10:00Z",
        )
        self.assertEqual(self.verifier.calls, after_admit + 3)

    def test_revoked_review_authority_blocks_all_durable_operations(self) -> None:
        receipt = self.service.admit(self.command)
        self.verifier.current = False
        with self.assertRaisesRegex(ActionResolutionError, "revoked"):
            self.service.admit(self.command)
        with self.assertRaisesRegex(ActionResolutionError, "revoked"):
            self.service.verify_current(receipt.receipt_id)
        with self.assertRaisesRegex(ActionResolutionError, "revoked"):
            self.service.revoke(
                receipt.receipt_id,
                reason_code="authority:withdrawn",
                revoked_at="2026-09-20T12:10:00Z",
            )
        self.assertEqual(self._counts(), (1, 4, 1, 0))

    def test_revocation_is_automatic_and_fail_closed(self) -> None:
        receipt = self.service.admit(self.command)
        revocation = self.service.revoke(
            receipt.receipt_id,
            reason_code="authority:withdrawn",
            revoked_at="2026-09-20T12:10:00Z",
        )
        self.assertEqual(revocation.to_dict()["receipt_id"], receipt.receipt_id)
        with self.assertRaisesRegex(ActionResolutionError, "revoked"):
            self.service.verify_current(receipt.receipt_id)
        with self.assertRaisesRegex(ActionResolutionError, "revoked"):
            self.service.admit(self.command)

    def test_authoritative_rotation_invalidates_current_proof(self) -> None:
        receipt = self.service.admit(self.command)
        self.authority.rotated = True
        with self.assertRaisesRegex(ActionResolutionError, "changed or was revoked"):
            self.service.verify_current(receipt.receipt_id)

    def test_cross_service_or_fabricated_proof_is_rejected(self) -> None:
        receipt = self.service.admit(self.command)
        proof = self.service.verify_current(receipt.receipt_id)
        other_path = Path(self.temporary.name) / "other.sqlite3"
        other = AuthenticatedActionAdmissionService(
            other_path,
            self.authority,
            self.verifier,
            self.material.registry,
        )
        other.initialize()
        with self.assertRaisesRegex(ActionResolutionError, "another service"):
            other.require_owned_current_proof(proof)

    def test_current_proof_binds_every_exposed_field_and_does_not_survive_restart(self) -> None:
        receipt = self.service.admit(self.command)
        mutations = {
            "receipt": self.receipt,
            "verified_at": "2026-09-20T12:06:00Z",
            "custody_sha256": digest("0"),
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                proof = self.service.verify_current(receipt.receipt_id)
                object.__setattr__(proof, field, value)
                with self.assertRaisesRegex(
                    ActionResolutionError, "another service|invalid"
                ):
                    self.service.require_owned_current_proof(proof)
        fresh = self.service.verify_current(receipt.receipt_id)
        restarted = AuthenticatedActionAdmissionService(
            self.database,
            self.authority,
            self.verifier,
            self.material.registry,
            clock=lambda: datetime(2026, 9, 20, 12, 6, tzinfo=UTC),
        )
        with self.assertRaisesRegex(ActionResolutionError, "another service"):
            restarted.require_owned_current_proof(fresh)

    def test_point_of_use_verification_rechecks_phase165_expiry(self) -> None:
        receipt = self.service.admit(self.command)
        with self.assertRaisesRegex(ActionResolutionError, "no longer current"):
            self.service.verify_current(
                receipt.receipt_id,
                evaluated_at="2026-09-20T13:01:00Z",
            )

    def test_revocation_cannot_predate_admission(self) -> None:
        receipt = self.service.admit(self.command)
        with self.assertRaisesRegex(ActionResolutionError, "predates admission"):
            self.service.revoke(
                receipt.receipt_id,
                reason_code="authority:withdrawn",
                revoked_at="2026-09-20T12:04:59Z",
            )
        self.assertEqual(self._counts(), (1, 4, 1, 0))

    def test_failure_rolls_back_assertions_budget_and_receipt(self) -> None:
        self.authority.fail_admission = True
        with self.assertRaisesRegex(ActionResolutionError, "Injected"):
            self.service.admit(self.command)
        self.assertEqual(self._counts(), (0, 0, 0, 0))
        self.authority.fail_admission = False
        self.service.admit(self.command)
        self.assertEqual(self._counts(), (1, 4, 1, 0))

    def test_resolver_identity_and_full_phase165_state_are_authoritative(self) -> None:
        self.authority.material = replace(
            self.material,
            resolver_profile_id="AOE-GA-D01-S01",
        )
        with self.assertRaisesRegex(ActionResolutionError, "resolver.*independent|independent"):
            self.service.admit(self.command)
        self.assertEqual(self._counts(), (0, 0, 0, 0))
        self.authority.material = replace(
            self.material,
            credential_lease=replace(
                self.material.credential_lease,
                permitted_action_sha256=digest("0"),
            ),
        )
        with self.assertRaisesRegex(ActionResolutionError, "prerequisites"):
            self.service.admit(self.command)
        self.assertEqual(self._counts(), (0, 0, 0, 0))
        self.authority.material = replace(
            self.material,
            budget=replace(
                self.material.budget,
                requests_used=self.material.budget.request_limit,
            ),
        )
        with self.assertRaisesRegex(ActionResolutionError, "admission denied"):
            self.service.admit(self.command)
        self.assertEqual(self._counts(), (0, 0, 0, 0))

    def test_assertion_replay_conflict_rolls_back_second_intent(self) -> None:
        self.service.admit(self.command)
        second = ActionAdmissionCommand(
            tenant_id=self.command.tenant_id,
            mission_id=self.command.mission_id,
            proposal_product_id=self.command.proposal_product_id,
            action_type=self.command.action_type,
            action_tier=self.command.action_tier,
            idempotency_key_sha256=digest("0"),
        )
        with self.assertRaisesRegex(StoreError, "durable replay"):
            self.service.admit(second)
        self.assertEqual(self._counts(), (1, 4, 1, 0))

    def test_concurrent_exact_replay_has_one_durable_result(self) -> None:
        with ThreadPoolExecutor(max_workers=2) as pool:
            receipts = list(pool.map(lambda _: self.service.admit(self.command), range(2)))
        self.assertEqual(receipts[0].document_json, receipts[1].document_json)
        self.assertEqual(self._counts(), (1, 4, 1, 0))

    def test_chronology_and_revocation_independence_fail_closed(self) -> None:
        self.authority.material = replace(
            self.material,
            approved_at="2026-09-20T11:50:00Z",
        )
        with self.assertRaisesRegex(ActionResolutionError, "predates"):
            self.service.admit(self.command)
        self.authority.material = self.material
        receipt = self.service.admit(self.command)
        self.authority.reuse_admission_for_revocation = True
        with self.assertRaisesRegex(ActionResolutionError, "reuse|independent"):
            self.service.revoke(
                receipt.receipt_id,
                reason_code="authority:withdrawn",
                revoked_at="2026-09-20T12:10:00Z",
            )
        self.assertEqual(self._counts(), (1, 4, 1, 0))

    def test_custody_tamper_and_wrong_idempotency_intent_fail(self) -> None:
        receipt = self.service.admit(self.command)
        conflict = ActionAdmissionCommand(
            tenant_id=self.command.tenant_id,
            mission_id=self.command.mission_id,
            proposal_product_id=self.command.proposal_product_id,
            action_type=self.command.action_type,
            action_tier=ActionTier.R4,
            idempotency_key_sha256=self.command.idempotency_key_sha256,
        )
        with self.assertRaisesRegex(StoreError, "different intent"):
            self.service.admit(conflict)
        connection = sqlite3.connect(self.database)
        try:
            connection.execute("DROP TRIGGER action_admission_receipts_no_update")
            connection.execute(
                "UPDATE action_admission_receipts SET custody_sha256 = ? WHERE receipt_id = ?",
                (digest("0"), receipt.receipt_id),
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaisesRegex(StoreError, "custody (?:hash|schema)"):
            self.service.verify_current(receipt.receipt_id)

    def test_initialize_does_not_repair_a_damaged_marked_store(self) -> None:
        connection = sqlite3.connect(self.database)
        try:
            connection.execute("DROP TRIGGER action_admission_receipts_no_update")
            connection.commit()
        finally:
            connection.close()
        with self.assertRaisesRegex(StoreError, "schema objects"):
            self.service.initialize()
        connection = sqlite3.connect(self.database)
        try:
            row = connection.execute(
                """
                SELECT 1 FROM sqlite_master
                WHERE type = 'trigger' AND name = 'action_admission_receipts_no_update'
                """
            ).fetchone()
            self.assertIsNone(row)
        finally:
            connection.close()

    def test_same_name_schema_substitution_is_rejected(self) -> None:
        connection = sqlite3.connect(self.database)
        try:
            connection.execute("DROP TRIGGER action_admission_receipts_no_update")
            connection.execute(
                """
                CREATE TRIGGER action_admission_receipts_no_update
                BEFORE UPDATE ON action_admission_receipts BEGIN
                    SELECT RAISE(ABORT, 'substituted');
                END
                """
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaisesRegex(StoreError, "schema objects"):
            self.service.admit(self.command)

    def test_rehashed_decision_substitution_is_rejected(self) -> None:
        receipt = self.service.admit(self.command)
        connection = sqlite3.connect(self.database)
        connection.row_factory = sqlite3.Row
        try:
            row = connection.execute(
                "SELECT * FROM action_admission_receipts WHERE receipt_id = ?",
                (receipt.receipt_id,),
            ).fetchone()
            self.assertIsNotNone(row)
            resolution = json.loads(row["resolution_json"])
            resolver = json.loads(
                connection.execute(
                    """
                    SELECT authorization_json FROM action_admission_assertion_uses
                    WHERE receipt_id = ? AND role = 'typed_resolver'
                    """,
                    (receipt.receipt_id,),
                ).fetchone()[0]
            )
            command = {
                "action_tier": resolution["action_tier"],
                "action_type": resolution["action_type"],
                "idempotency_key_sha256": resolution["idempotency_key_sha256"],
                "mission_id": resolution["mission_id"],
                "proposal_product_id": resolution["proposal_product_id"],
                "tenant_id": resolution["tenant_id"],
            }
            substituted_decision = {"status": "admitted_contract_only"}
            custody = {
                "authority_state": json.loads(row["authority_state_json"]),
                "authority_state_sha256": row["authority_state_sha256"],
                "command": command,
                "command_sha256": row["command_sha256"],
                "created_at": row["created_at"],
                "decision": substituted_decision,
                "quorum": json.loads(row["quorum_json"]),
                "receipt": json.loads(row["receipt_json"]),
                "request": json.loads(row["request_json"]),
                "resolution": resolution,
                "resolver_authorization": resolver,
                "review_evidence": json.loads(row["review_evidence_json"]),
                "review_evidence_sha256": row["review_evidence_sha256"],
            }
            custody_sha256 = durable_admission._canonical_sha256(
                {"domain": durable_admission.CUSTODY_DOMAIN, "custody": custody}
            )
            trigger_sql = connection.execute(
                """
                SELECT sql FROM sqlite_master
                WHERE type = 'trigger' AND name = 'action_admission_receipts_no_update'
                """
            ).fetchone()[0]
            connection.execute("DROP TRIGGER action_admission_receipts_no_update")
            connection.execute(
                """
                UPDATE action_admission_receipts
                SET decision_json = ?, custody_sha256 = ?
                WHERE receipt_id = ?
                """,
                (
                    _canonical_json(substituted_decision),
                    custody_sha256,
                    receipt.receipt_id,
                ),
            )
            connection.execute(trigger_sql)
            connection.commit()
        finally:
            connection.close()
        with self.assertRaisesRegex(StoreError, "chain"):
            self.service.verify_current(receipt.receipt_id)

    def test_assertion_consumption_chronology_substitution_is_rejected(self) -> None:
        receipt = self.service.admit(self.command)
        connection = sqlite3.connect(self.database)
        try:
            trigger_sql = connection.execute(
                """
                SELECT sql FROM sqlite_master
                WHERE type = 'trigger' AND name = 'action_admission_assertion_uses_no_update'
                """
            ).fetchone()[0]
            connection.execute("DROP TRIGGER action_admission_assertion_uses_no_update")
            connection.execute(
                """
                UPDATE action_admission_assertion_uses
                SET consumed_at = ?
                WHERE receipt_id = ? AND role = 'typed_resolver'
                """,
                ("2026-09-20T12:06:00Z", receipt.receipt_id),
            )
            connection.execute(trigger_sql)
            connection.commit()
        finally:
            connection.close()
        with self.assertRaisesRegex(StoreError, "authorization columns"):
            self.service.verify_current(receipt.receipt_id)


if __name__ == "__main__":
    unittest.main()

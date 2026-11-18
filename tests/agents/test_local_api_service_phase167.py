from __future__ import annotations

import json
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from jsonschema import Draft202012Validator

from sunderkey.local_api_service import (
    AccessCheck,
    AccessContext,
    AccessDecision,
    AdmissionStatus,
    CommitCommand,
    CommitResult,
    DecisionStatus,
    LocalApiService,
    LocalApiServiceError,
    MissionState,
    MutationAdmission,
    MutationCheck,
    Operation,
    ResourceKind,
    ResourceRecord,
    ResponseStatus,
    ServiceRequest,
    canonical_sha256,
    service_capability_manifest,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "registry" / "schemas" / "local-api-service-v1.schema.json"
NOW = "2026-09-20T12:00:00Z"
LATER = "2026-09-20T12:10:00Z"


class FakeAuthorizer:
    def __init__(self) -> None:
        self.checks: list[AccessCheck] = []
        self.status = DecisionStatus.ALLOWED
        self.rebind_tenant = False

    def authorize(self, check: AccessCheck) -> AccessDecision:
        self.checks.append(check)
        return AccessDecision(
            decision_ref="authzref:decision-001",
            status=self.status,
            request_sha256=check.request_sha256,
            tenant_id="tenant-other" if self.rebind_tenant else check.tenant_id,
            context_id=check.context_id,
            principal_id=check.principal_id,
            session_ref=check.session_ref,
            permission=check.permission,
            valid_through=LATER,
            audit_ref="auditref:authorization-001",
        )


class FakeAdmitter:
    def __init__(self) -> None:
        self.checks: list[MutationCheck] = []
        self.status = AdmissionStatus.ADMITTED
        self.rebind_operation = False

    def admit(self, check: MutationCheck) -> MutationAdmission:
        self.checks.append(check)
        operation = Operation.CREATE_REPORT if self.rebind_operation else check.operation
        return MutationAdmission(
            admission_ref="admitref:admission-001",
            status=self.status,
            request_sha256=check.request_sha256,
            idempotency_sha256=check.idempotency_sha256,
            authorization_ref=check.authorization_ref,
            tenant_id=check.tenant_id,
            context_id=check.context_id,
            principal_id=check.principal_id,
            operation=operation,
            resource_kind=check.resource_kind,
            resource_id=check.resource_id,
            expected_concurrency_token=check.expected_concurrency_token,
            valid_through=LATER,
            audit_ref="auditref:admission-001",
        )


class FakeRepository:
    def __init__(self) -> None:
        self.records: dict[tuple[ResourceKind, str, str, str], ResourceRecord] = {}
        self.idempotency: dict[tuple[str, str, str], CommitResult] = {}
        self.commits: list[CommitCommand] = []

    @staticmethod
    def _key(
        kind: ResourceKind, tenant_id: str, context_id: str, resource_id: str
    ) -> tuple[ResourceKind, str, str, str]:
        return kind, tenant_id, context_id, resource_id

    def get(
        self, kind: ResourceKind, tenant_id: str, context_id: str, resource_id: str
    ) -> ResourceRecord | None:
        return self.records.get(self._key(kind, tenant_id, context_id, resource_id))

    def list_after(
        self,
        kind: ResourceKind,
        tenant_id: str,
        context_id: str,
        after_resource_id: str | None,
        limit: int,
    ) -> tuple[ResourceRecord, ...]:
        records = sorted(
            (
                record
                for (stored_kind, tenant, context, _), record in self.records.items()
                if stored_kind is kind and tenant == tenant_id and context == context_id
            ),
            key=lambda item: item.resource_id,
        )
        return tuple(
            record
            for record in records
            if after_resource_id is None or record.resource_id > after_resource_id
        )[:limit]

    def lookup_idempotency(
        self, tenant_id: str, context_id: str, idempotency_sha256: str
    ) -> CommitResult | None:
        result = self.idempotency.get((tenant_id, context_id, idempotency_sha256))
        return None if result is None else replace(result, replayed=True)

    def commit(self, command: CommitCommand) -> CommitResult:
        record = command.record
        idempotency_key = (
            record.tenant_id,
            record.context_id,
            command.idempotency_sha256,
        )
        prior_result = self.idempotency.get(idempotency_key)
        if prior_result is not None:
            if prior_result.request_sha256 != command.request_sha256:
                raise LocalApiServiceError("idempotency conflict")
            return replace(prior_result, replayed=True)
        key = self._key(
            record.resource_kind,
            record.tenant_id,
            record.context_id,
            record.resource_id,
        )
        live = self.records.get(key)
        live_token = None if live is None else live.concurrency_token
        if live_token != command.expected_concurrency_token:
            raise LocalApiServiceError("atomic concurrency conflict")
        if command.prior_record != live:
            raise LocalApiServiceError("prior read changed before commit")
        result = CommitResult(
            request_sha256=command.request_sha256,
            idempotency_sha256=command.idempotency_sha256,
            record=record,
            audit_entry=command.audit_entry,
            integration_event=command.integration_event,
            replayed=False,
        )
        self.records[key] = record
        self.idempotency[idempotency_key] = result
        self.commits.append(command)
        return result


class LocalApiServicePhase167Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.repository = FakeRepository()
        self.authorizer = FakeAuthorizer()
        self.admitter = FakeAdmitter()
        self.service = LocalApiService(self.repository, self.authorizer, self.admitter)
        self.access = AccessContext(
            tenant_id="tenant-a",
            context_id="context-red",
            principal_id="principal-operator",
            session_ref="session-verified",
        )

    def request(
        self,
        operation: Operation,
        kind: ResourceKind,
        resource_id: str | None = None,
        payload: dict | None = None,
        *,
        token: str | None = None,
        idempotency: str | None = None,
        cursor: str | None = None,
        page_size: int | None = None,
        request_id: str = "request-001",
        access: AccessContext | None = None,
    ) -> ServiceRequest:
        return ServiceRequest(
            request_id=request_id,
            operation=operation,
            access=self.access if access is None else access,
            requested_at=NOW,
            resource_kind=kind,
            resource_id=resource_id,
            payload=payload,
            expected_concurrency_token=token,
            idempotency_key=idempotency,
            cursor=cursor,
            page_size=page_size,
        )

    @staticmethod
    def asset_payload(name: str = "Public API") -> dict:
        return {
            "credential_refs": ["credentialref:asset-001"],
            "eligibility": "admitted",
            "environment": "authorized_test",
            "exclusion_refs": ["exclusionref:none"],
            "name": name,
            "owner_ref": "ownerref:team-red",
            "target_refs": ["targetref:asset-001"],
        }

    @staticmethod
    def mission_payload(state: str = "draft") -> dict:
        return {
            "asset_refs": ["assetref:asset-001"],
            "budget_ref": "budgetref:mission-001",
            "schedule_ref": "schedref:mission-001",
            "scope_ref": "scoperef:mission-001",
            "state": state,
        }

    def create_asset(self, resource_id: str = "asset-001", suffix: str = "001"):
        return self.service.handle(
            self.request(
                Operation.CREATE_ASSET,
                ResourceKind.ASSET,
                resource_id,
                self.asset_payload(resource_id),
                idempotency=f"idem:create-asset-{suffix}-00000001",
                request_id=f"request-asset-{suffix}",
            )
        )

    def test_manifest_is_honest_about_effects_and_covers_p5_1_through_p5_9(self) -> None:
        manifest = service_capability_manifest()
        self.assertEqual(manifest["capability_packages"], [f"P5.{index}" for index in range(1, 10)])
        self.assertEqual(manifest["effects"]["network"], "none")
        self.assertEqual(manifest["effects"]["server"], "none")
        self.assertEqual(manifest["effects"]["persistence"], "injected")
        self.assertEqual(len(manifest["resource_kinds"]), 10)

    def test_all_product_resource_mutations_emit_atomic_audit_and_integration_records(self) -> None:
        cases = [
            (
                Operation.CREATE_ASSET,
                ResourceKind.ASSET,
                "asset-all",
                self.asset_payload(),
            ),
            (
                Operation.CREATE_MISSION,
                ResourceKind.MISSION,
                "mission-all",
                self.mission_payload(),
            ),
            (
                Operation.UPSERT_FINDING,
                ResourceKind.FINDING,
                "finding-all",
                {
                    "affected_asset_refs": ["assetref:asset-all"],
                    "evidence_refs": ["evidref:evidence-all"],
                    "owner_ref": "ownerref:team-red",
                    "remediation_ref": "remediationref:finding-all",
                    "retest_refs": [],
                    "severity": "high",
                    "status": "validated",
                    "title": "Bounded issue",
                    "validation_ref": "validationref:finding-all",
                },
            ),
            (
                Operation.APPEND_EVIDENCE,
                ResourceKind.EVIDENCE,
                "evidence-all",
                {
                    "action_ref": "actionref:action-all",
                    "authorization_ref": "authorizationref:action-all",
                    "cleanup_ref": "cleanupref:action-all",
                    "finding_ref": "findingref:finding-all",
                    "result_ref": "resultref:action-all",
                },
            ),
            (
                Operation.CREATE_REPORT,
                ResourceKind.REPORT,
                "report-all",
                {
                    "evidence_refs": ["evidref:evidence-all"],
                    "finding_refs": ["findingref:finding-all"],
                    "record_set_sha256": canonical_sha256({"records": ["finding-all"]}),
                    "report_type": "technical",
                },
            ),
            (
                Operation.RECORD_REMEDIATION,
                ResourceKind.REMEDIATION,
                "remediation-all",
                {
                    "closure_status": "retest_pending",
                    "developer_evidence_refs": ["evidref:developer-all"],
                    "finding_ref": "findingref:finding-all",
                    "guidance_ref": "guidanceref:finding-all",
                    "regression_ref": "regressionref:finding-all",
                    "retest_ref": "retestref:finding-all",
                },
            ),
            (
                Operation.RECORD_APPROVAL,
                ResourceKind.APPROVAL,
                "approval-all",
                {
                    "approver_ref": "principalref:control-all",
                    "decision": "approved",
                    "decision_evidence_ref": "evidref:approval-all",
                    "subject_ref": "missionref:mission-all",
                },
            ),
            (
                Operation.UPDATE_HEALTH,
                ResourceKind.HEALTH,
                "health-all",
                {
                    "component_ref": "componentref:control-plane",
                    "observation_ref": "observationref:health-all",
                    "observed_at": NOW,
                    "state": "healthy",
                },
            ),
            (
                Operation.PUBLISH_OPERATOR_PROJECTION,
                ResourceKind.OPERATOR_PROJECTION,
                "projection-all",
                {
                    "approval_refs": ["approvalref:approval-all"],
                    "blocker_refs": [],
                    "budget_ref": "budgetref:mission-all",
                    "coverage_ref": "coverageref:mission-all",
                    "graph_ref": "graphref:mission-all",
                    "health_refs": ["healthref:health-all"],
                    "mission_ref": "missionref:mission-all",
                    "worker_ref": "workerref:coordinator-all",
                },
            ),
        ]
        for index, (operation, kind, resource_id, payload) in enumerate(cases):
            with self.subTest(operation=operation):
                response = self.service.handle(
                    self.request(
                        operation,
                        kind,
                        resource_id,
                        payload,
                        idempotency=f"idem:all-resource-{index:02d}-00000001",
                        request_id=f"request-all-{index:02d}",
                    )
                )
                self.assertEqual(response.status, ResponseStatus.COMPLETED)
                self.assertIn(response.mutation_audit_ref, response.resource.audit_refs)
                self.assertEqual(
                    response.integration_event.audit_ref,
                    response.mutation_audit_ref,
                )
        self.assertEqual(len(self.repository.commits), len(cases))

    def test_asset_update_preserves_audit_chain_and_checks_concurrency(self) -> None:
        created = self.create_asset()
        updated = self.service.handle(
            self.request(
                Operation.UPDATE_ASSET,
                ResourceKind.ASSET,
                "asset-001",
                self.asset_payload("Updated API"),
                token=created.resource.concurrency_token,
                idempotency="idem:update-asset-001-00000001",
                request_id="request-asset-update",
            )
        )
        self.assertEqual(updated.resource.version, 2)
        self.assertEqual(updated.resource.audit_refs[:-1], created.resource.audit_refs)
        self.assertNotEqual(updated.resource.concurrency_token, created.resource.concurrency_token)
        with self.assertRaisesRegex(LocalApiServiceError, "stale"):
            self.service.handle(
                self.request(
                    Operation.UPDATE_ASSET,
                    ResourceKind.ASSET,
                    "asset-001",
                    self.asset_payload("Stale"),
                    token=created.resource.concurrency_token,
                    idempotency="idem:update-asset-002-00000001",
                    request_id="request-asset-stale",
                )
            )

    def test_mission_lifecycle_allows_only_declared_transition_edges(self) -> None:
        created = self.service.handle(
            self.request(
                Operation.CREATE_MISSION,
                ResourceKind.MISSION,
                "mission-001",
                self.mission_payload(MissionState.DRAFT),
                idempotency="idem:create-mission-001-000001",
            )
        )
        ready = self.service.handle(
            self.request(
                Operation.TRANSITION_MISSION,
                ResourceKind.MISSION,
                "mission-001",
                self.mission_payload(MissionState.READY),
                token=created.resource.concurrency_token,
                idempotency="idem:ready-mission-001-000001",
                request_id="request-002",
            )
        )
        self.assertEqual(ready.resource.payload["state"], "ready")
        with self.assertRaisesRegex(LocalApiServiceError, "not allowed"):
            self.service.handle(
                self.request(
                    Operation.TRANSITION_MISSION,
                    ResourceKind.MISSION,
                    "mission-001",
                    self.mission_payload(MissionState.COMPLETED),
                    token=ready.resource.concurrency_token,
                    idempotency="idem:complete-too-soon-000001",
                    request_id="request-003",
                )
            )

    def test_authorization_and_admission_bindings_fail_closed(self) -> None:
        request = self.request(
            Operation.CREATE_ASSET,
            ResourceKind.ASSET,
            "asset-auth",
            self.asset_payload(),
            idempotency="idem:create-asset-auth-000001",
        )
        self.authorizer.rebind_tenant = True
        with self.assertRaisesRegex(LocalApiServiceError, "authorization"):
            self.service.handle(request)
        self.authorizer.rebind_tenant = False
        self.admitter.status = AdmissionStatus.REJECTED
        with self.assertRaisesRegex(LocalApiServiceError, "admission"):
            self.service.handle(request)
        self.admitter.status = AdmissionStatus.ADMITTED
        self.admitter.rebind_operation = True
        with self.assertRaisesRegex(LocalApiServiceError, "admission"):
            self.service.handle(request)
        self.assertEqual(self.repository.commits, [])

    def test_idempotent_retry_replays_one_commit_and_conflict_is_rejected(self) -> None:
        request = self.request(
            Operation.CREATE_ASSET,
            ResourceKind.ASSET,
            "asset-replay",
            self.asset_payload(),
            idempotency="idem:create-asset-replay-0001",
        )
        first = self.service.handle(request)
        replay = self.service.handle(request)
        self.assertEqual(first.status, ResponseStatus.COMPLETED)
        self.assertEqual(replay.status, ResponseStatus.REPLAYED)
        self.assertEqual(first.resource, replay.resource)
        self.assertEqual(len(self.repository.commits), 1)
        different = replace(request, request_id="request-different")
        with self.assertRaisesRegex(LocalApiServiceError, "rebound"):
            self.service.handle(different)

    def test_pagination_is_stable_and_cursor_is_context_bound(self) -> None:
        for index in range(3):
            self.create_asset(f"asset-{index:03d}", f"{index:03d}")
        first = self.service.handle(
            self.request(
                Operation.LIST_RESOURCES,
                ResourceKind.ASSET,
                page_size=2,
                request_id="request-list-001",
            )
        )
        self.assertEqual(
            [item.resource_id for item in first.page.items], ["asset-000", "asset-001"]
        )
        self.assertIsNotNone(first.page.next_cursor)
        second = self.service.handle(
            self.request(
                Operation.LIST_RESOURCES,
                ResourceKind.ASSET,
                cursor=first.page.next_cursor,
                page_size=2,
                request_id="request-list-002",
            )
        )
        self.assertEqual([item.resource_id for item in second.page.items], ["asset-002"])
        other = replace(self.access, context_id="context-other")
        with self.assertRaisesRegex(LocalApiServiceError, "rebound"):
            self.service.handle(
                self.request(
                    Operation.LIST_RESOURCES,
                    ResourceKind.ASSET,
                    cursor=first.page.next_cursor,
                    page_size=2,
                    request_id="request-list-other",
                    access=other,
                )
            )

    def test_repository_cross_context_record_is_rejected(self) -> None:
        self.create_asset()
        other = replace(self.access, tenant_id="tenant-other")
        cross_context = self.service.handle(
            self.request(
                Operation.CREATE_ASSET,
                ResourceKind.ASSET,
                "asset-001",
                self.asset_payload(),
                idempotency="idem:create-other-asset-000001",
                request_id="request-other-asset",
                access=other,
            )
        )
        key = self.repository._key(ResourceKind.ASSET, "tenant-a", "context-red", "asset-001")
        self.repository.records[key] = cross_context.resource
        with self.assertRaisesRegex(LocalApiServiceError, "cross-context"):
            self.service.handle(
                self.request(
                    Operation.GET_RESOURCE,
                    ResourceKind.ASSET,
                    "asset-001",
                    request_id="request-get-cross-context",
                )
            )

    def test_get_rejects_a_different_valid_resource_in_the_same_context(self) -> None:
        wanted = self.create_asset()
        other = self.create_asset("asset-other", "002")
        request = self.request(Operation.GET_RESOURCE, ResourceKind.ASSET, "asset-001")
        self.assertEqual(self.service.handle(request).resource, wanted.resource)
        before = len(self.repository.commits)
        with (
            mock.patch.object(self.repository, "get", return_value=other.resource),
            self.assertRaisesRegex(LocalApiServiceError, "resource identity"),
        ):
            self.service.handle(request)
        self.assertEqual(len(self.repository.commits), before)

    def test_mutation_rejects_a_different_existing_resource_before_admission(self) -> None:
        wanted = self.create_asset()
        other = self.create_asset("asset-other", "002")
        request = self.request(
            Operation.UPDATE_ASSET,
            ResourceKind.ASSET,
            "asset-001",
            self.asset_payload("Updated API"),
            token=wanted.resource.concurrency_token,
            idempotency="idem:update-resource-00000001",
        )
        before = len(self.repository.commits)
        with (
            mock.patch.object(self.repository, "get", return_value=other.resource),
            mock.patch.object(self.admitter, "admit") as admit,
            self.assertRaisesRegex(LocalApiServiceError, "resource identity"),
        ):
            self.service.handle(request)
        admit.assert_not_called()
        self.assertEqual(len(self.repository.commits), before)

    def test_commit_and_replay_reject_a_different_valid_resource(self) -> None:
        self.create_asset("asset-other", "002")
        original = next(iter(self.repository.idempotency.values()))
        request = self.request(
            Operation.CREATE_ASSET,
            ResourceKind.ASSET,
            "asset-wanted",
            self.asset_payload("Wanted API"),
            idempotency="idem:create-wanted-00000001",
        )
        wrong = replace(
            original,
            request_sha256=request.request_sha256,
            idempotency_sha256=request.idempotency_sha256,
        )
        for method in ("commit", "lookup_idempotency"):
            with (
                self.subTest(method=method),
                mock.patch.object(self.repository, method, return_value=wrong),
                self.assertRaisesRegex(LocalApiServiceError, "resource identity"),
            ):
                self.service.handle(request)

    def test_schema_accepts_response_and_rejects_unknown_fields(self) -> None:
        response = self.create_asset().to_dict()
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(response)
        tampered = dict(response)
        tampered["unexpected"] = True
        errors = list(Draft202012Validator(schema).iter_errors(tampered))
        self.assertTrue(errors)

    def test_public_symbols_are_importable_without_runtime_effects(self) -> None:
        import sunderkey.local_api_service as module

        expected = {
            "AccessAuthorizer",
            "AccessCheck",
            "AccessContext",
            "AccessDecision",
            "AdmissionStatus",
            "AuditEntry",
            "CommitCommand",
            "CommitResult",
            "DecisionStatus",
            "IntegrationEvent",
            "LocalApiService",
            "LocalApiServiceError",
            "MissionState",
            "MutationAdmitter",
            "MutationAdmission",
            "MutationCheck",
            "Operation",
            "ResourceKind",
            "ResourceRecord",
            "ResponseStatus",
            "ServicePage",
            "ServiceRepository",
            "ServiceRequest",
            "ServiceResponse",
            "canonical_json",
            "canonical_sha256",
            "service_capability_manifest",
        }
        self.assertTrue(expected.issubset(set(dir(module))))

    def test_public_package_exports_service_boundary(self) -> None:
        import sunderkey

        self.assertIs(sunderkey.LocalApiService, LocalApiService)
        self.assertIs(sunderkey.LocalApiServiceRequest, ServiceRequest)
        self.assertIs(sunderkey.LocalApiResourceRecord, ResourceRecord)
        self.assertEqual(
            sunderkey.local_api_service_capability_manifest(),
            service_capability_manifest(),
        )


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from jsonschema import Draft202012Validator

import sunderkey
from sunderkey.local_api_runtime_adapter import SQLiteServiceRepository
from sunderkey.local_api_service import (
    AccessCheck,
    AccessContext,
    AccessDecision,
    AdmissionStatus,
    DecisionStatus,
    LocalApiService,
    LocalApiServiceError,
    MutationAdmission,
    MutationCheck,
    Operation,
    ResourceKind,
    ServiceRequest,
)
from sunderkey.target_context import (
    TargetContextKind,
    TargetContextLimits,
    TargetContextProvenance,
    ingest_target_context_bytes,
)
from sunderkey.target_context_attachment_api import (
    TargetContextAttachmentApi,
    TargetContextAttachmentError,
    TargetContextAttachmentReceipt,
    TargetContextAttachmentRequest,
    TargetContextSourceAttachment,
    target_context_attachment_capability_manifest,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "registry" / "schemas" / "target-context-attachment-api-v1.schema.json"
NOW = "2026-09-20T12:00:00Z"
LATER = "2026-09-20T12:10:00Z"


class BoundAuthorizer:
    def authorize(self, check: AccessCheck) -> AccessDecision:
        return AccessDecision(
            decision_ref="authzref:target-context-attachment",
            status=DecisionStatus.ALLOWED,
            request_sha256=check.request_sha256,
            tenant_id=check.tenant_id,
            context_id=check.context_id,
            principal_id=check.principal_id,
            session_ref=check.session_ref,
            permission=check.permission,
            valid_through=LATER,
            audit_ref="auditref:target-context-attachment-authz",
        )


class BoundAdmitter:
    def admit(self, check: MutationCheck) -> MutationAdmission:
        return MutationAdmission(
            admission_ref="admitref:target-context-attachment",
            status=AdmissionStatus.ADMITTED,
            request_sha256=check.request_sha256,
            idempotency_sha256=check.idempotency_sha256,
            authorization_ref=check.authorization_ref,
            tenant_id=check.tenant_id,
            context_id=check.context_id,
            principal_id=check.principal_id,
            operation=check.operation,
            resource_kind=check.resource_kind,
            resource_id=check.resource_id,
            expected_concurrency_token=check.expected_concurrency_token,
            valid_through=LATER,
            audit_ref="auditref:target-context-attachment-admission",
        )


class RebindingService(LocalApiService):
    def __init__(self, service: LocalApiService, mutation) -> None:
        self.service = service
        self.mutation = mutation

    def handle(self, request: ServiceRequest):
        return self.mutation(self.service.handle(request))


class TargetContextAttachmentApiPhase175Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.repository = SQLiteServiceRepository(Path(self.temporary.name) / "attachment.sqlite3")
        self.local_service = LocalApiService(self.repository, BoundAuthorizer(), BoundAdmitter())
        self.api = TargetContextAttachmentApi(self.local_service)
        self.access = AccessContext(
            tenant_id="tenant-a",
            context_id="context-red",
            principal_id="principal-operator",
            session_ref="session-verified",
        )
        self.provenance = TargetContextProvenance(
            source_id="upload.phase175.1",
            supplied_by="principal.operator.1",
            collected_at=NOW,
        )

    def request(
        self,
        content: bytes = b'{"openapi":"3.1.0","paths":{}}',
        *,
        idempotency_key: str = "idem:target-context-attach-0001",
        name: str = "openapi.json",
        limits: TargetContextLimits | None = None,
    ) -> TargetContextAttachmentRequest:
        return TargetContextAttachmentRequest(
            request_id="request-target-context-001",
            access=self.access,
            requested_at=NOW,
            idempotency_key=idempotency_key,
            mission_id="MISSION-175-001",
            authority_ref="AUTH-175-001",
            expected_authorization_ref="authzref:target-context-attachment",
            expected_authorization_audit_ref="auditref:target-context-attachment-authz",
            sources=(
                TargetContextSourceAttachment(
                    name=name,
                    content=content,
                    media_type="application/json",
                    kind=TargetContextKind.OPENAPI,
                ),
            ),
            provenance=self.provenance,
            limits=limits,
        )

    def test_bytes_attach_as_content_addressed_resource_without_raw_content(self) -> None:
        secret = b"gh" + b"p_" + b"abcdefghijklmnopqrstuvwxyz123456"
        request = self.request(b'{"openapi":"3.1.0","paths":{},"x-note":"' + secret + b'"}')
        receipt = self.api.attach(request)
        self.assertEqual(receipt.status, "completed")
        self.assertEqual(receipt.bundle_status, "quarantined")
        self.assertEqual(receipt.redaction_count, 1)
        record = self.repository.get(
            ResourceKind.TARGET_CONTEXT,
            self.access.tenant_id,
            self.access.context_id,
            receipt.bundle_id,
        )
        self.assertIsNotNone(record)
        self.assertEqual(record.resource_id, record.payload["bundle"]["bundle_id"])
        stored = json.dumps(record.to_dict(), sort_keys=True)
        self.assertNotIn(secret.decode("ascii"), stored)
        self.assertNotIn(secret.decode("ascii"), receipt.to_json())
        self.assertEqual(self.repository.verify_integrity()["resources"], 1)

    def test_exact_retry_replays_one_commit_and_changed_content_conflicts(self) -> None:
        request = self.request()
        completed = self.api.attach(request)
        replayed = self.api.attach(request)
        self.assertEqual(completed.status, "completed")
        self.assertEqual(replayed.status, "replayed")
        self.assertEqual(completed.bundle_id, replayed.bundle_id)
        self.assertEqual(completed.service_request_sha256, replayed.service_request_sha256)
        self.assertNotEqual(completed.receipt_id, replayed.receipt_id)
        counts = self.repository.verify_integrity()
        self.assertEqual(counts["resources"], 1)
        self.assertEqual(counts["idempotency_results"], 1)
        changed = self.request(b'{"openapi":"3.1.0","paths":{"/x":{}}}')
        with self.assertRaisesRegex(LocalApiServiceError, "rebound"):
            self.api.attach(changed)

    def test_existing_bundle_is_revalidated_and_provenance_is_preserved(self) -> None:
        bundle = ingest_target_context_bytes(
            b"# Local documentation\n",
            name="README.md",
            media_type="text/markdown",
            kind=TargetContextKind.DOCUMENTATION,
            mission_id="MISSION-175-002",
            authority_ref="AUTH-175-002",
            provenance=self.provenance,
        )
        request = TargetContextAttachmentRequest(
            request_id="request-target-context-002",
            access=self.access,
            requested_at=NOW,
            idempotency_key="idem:target-context-bundle-0002",
            mission_id=bundle.mission_id,
            authority_ref=bundle.authority_ref,
            expected_authorization_ref="authzref:target-context-attachment",
            expected_authorization_audit_ref="auditref:target-context-attachment-authz",
            bundle=bundle,
        )
        round_trip = TargetContextAttachmentRequest.from_dict(request.to_dict())
        self.assertEqual(round_trip.bundle, bundle)
        receipt = self.api.attach(round_trip)
        self.assertEqual(receipt.provenance, self.provenance)
        self.assertEqual(receipt.bundle_sha256, bundle.bundle_sha256)

    def test_traversal_media_limits_and_bundle_tampering_fail_closed(self) -> None:
        with self.assertRaisesRegex(TargetContextAttachmentError, "rejected"):
            self.api.attach(self.request(b"pass\n", name="../escape.py"))
        with self.assertRaisesRegex(TargetContextAttachmentError, "rejected"):
            self.api.attach(
                self.request(
                    b'{"openapi":"3.1.0","paths":{}}',
                    limits=TargetContextLimits(max_input_bytes=8),
                )
            )
        with self.assertRaisesRegex(TargetContextAttachmentError, "rejected"):
            self.api.attach(self.request(b"MZ", name="payload.exe"))

        bundle = ingest_target_context_bytes(
            b"notes\n",
            name="notes.txt",
            mission_id="MISSION-175-003",
            authority_ref="AUTH-175-003",
            provenance=self.provenance,
        )
        tampered = bundle.to_dict()
        tampered["summary"]["artifact_count"] = 2
        with self.assertRaises(TargetContextAttachmentError):
            TargetContextAttachmentRequest.from_dict(
                {
                    "access": {
                        "context_id": self.access.context_id,
                        "principal_id": self.access.principal_id,
                        "session_ref": self.access.session_ref,
                        "tenant_id": self.access.tenant_id,
                    },
                    "authority_ref": bundle.authority_ref,
                    "bundle": tampered,
                    "expected_authorization_audit_ref": "auditref:target-context-attachment-authz",
                    "expected_authorization_ref": "authzref:target-context-attachment",
                    "idempotency_key": "idem:target-context-bundle-0003",
                    "input_mode": "context_bundle",
                    "limits": None,
                    "mission_id": bundle.mission_id,
                    "operation": "attach_target_context",
                    "provenance": None,
                    "request_id": "request-target-context-003",
                    "requested_at": NOW,
                    "schema_version": 1,
                    "sources": [],
                }
            )

    def test_request_receipt_round_trip_schema_and_tamper_detection(self) -> None:
        request = self.request()
        serialized = request.to_json()
        self.assertEqual(TargetContextAttachmentRequest.from_json(serialized), request)
        rebound = replace(
            request,
            expected_authorization_ref="authzref:substituted-authorization",
        )
        self.assertNotEqual(rebound.request_sha256, request.request_sha256)
        with self.assertRaisesRegex(TargetContextAttachmentError, "invalid"):
            replace(request, expected_authorization_ref="admitref:wrong-namespace")
        receipt = self.api.attach(request)
        self.assertEqual(TargetContextAttachmentReceipt.from_dict(receipt.to_dict()), receipt)
        tampered = receipt.to_dict()
        tampered["artifact_count"] += 1
        with self.assertRaisesRegex(TargetContextAttachmentError, "identity"):
            TargetContextAttachmentReceipt.from_dict(tampered)

        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        validator.validate(request.to_dict())
        validator.validate(receipt.to_dict())
        extra = request.to_dict()
        extra["unexpected"] = True
        self.assertTrue(list(validator.iter_errors(extra)))

    def test_direct_local_service_requires_bundle_id_as_resource_id(self) -> None:
        bundle = ingest_target_context_bytes(
            b"notes\n",
            name="notes.txt",
            mission_id="MISSION-175-004",
            authority_ref="AUTH-175-004",
            provenance=self.provenance,
        )
        request = ServiceRequest(
            request_id="request-target-context-direct",
            operation=Operation.ATTACH_TARGET_CONTEXT,
            access=self.access,
            requested_at=NOW,
            resource_kind=ResourceKind.TARGET_CONTEXT,
            resource_id="TCB-SUBSTITUTED",
            payload={"bundle": bundle.to_dict()},
            idempotency_key="idem:target-context-direct-0004",
        )
        with self.assertRaisesRegex(LocalApiServiceError, "bundle_id"):
            self.local_service.handle(request)

    def test_rebound_service_response_fields_fail_before_receipt(self) -> None:
        request = self.request()

        def wrong_event(response):
            return replace(
                response,
                integration_event=replace(
                    response.integration_event,
                    resource_id="TCB-SUBSTITUTED",
                ),
            )

        mutations = (
            lambda response: replace(response, request_id="request-substituted-001"),
            lambda response: replace(
                response,
                request_sha256="sha256:" + "0" * 64,
            ),
            wrong_event,
            lambda response: replace(
                response,
                authorization_ref="authzref:substituted-authorization",
            ),
            lambda response: replace(
                response,
                authorization_audit_ref="auditref:substituted-audit",
            ),
            lambda response: replace(
                response,
                mutation_audit_ref="auditref:substituted-mutation",
            ),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                api = TargetContextAttachmentApi(RebindingService(self.local_service, mutation))
                with self.assertRaisesRegex(
                    TargetContextAttachmentError,
                    "invalid attachment result",
                ):
                    api.attach(request)

    def test_manifest_is_explicit_about_limits_storage_and_nonclaims(self) -> None:
        manifest = target_context_attachment_capability_manifest()
        self.assertEqual(manifest["accepted_inputs"], ["caller_bytes", "context_bundle"])
        self.assertTrue(manifest["content_addressed_resource"])
        self.assertFalse(manifest["raw_content_persisted"])
        self.assertEqual(manifest["effects"]["network"], "none")
        self.assertEqual(manifest["effects"]["filesystem"], "none")
        self.assertEqual(manifest["effects"]["authority"], "none")
        self.assertEqual(manifest["effects"]["qualification"], "none")
        self.assertEqual(manifest["effects"]["runtime"], "none")

    def test_source_serialization_binds_size_and_hash(self) -> None:
        source = self.request().sources[0]
        raw = source.to_dict()
        self.assertEqual(TargetContextSourceAttachment.from_dict(raw), source)
        with self.assertRaisesRegex(TargetContextAttachmentError, "size"):
            TargetContextSourceAttachment.from_dict({**raw, "size_bytes": raw["size_bytes"] + 1})
        with self.assertRaisesRegex(TargetContextAttachmentError, "hash"):
            TargetContextSourceAttachment.from_dict({**raw, "content_sha256": "sha256:" + "0" * 64})

    def test_public_symbols_are_importable_without_effects(self) -> None:
        import sunderkey.target_context_attachment_api as module

        expected = {
            "TargetContextAttachmentApi",
            "TargetContextAttachmentError",
            "TargetContextAttachmentReceipt",
            "TargetContextAttachmentRequest",
            "TargetContextSourceAttachment",
            "target_context_attachment_capability_manifest",
        }
        self.assertTrue(expected.issubset(set(dir(module))))
        self.assertIs(sunderkey.TargetContextAttachmentApi, TargetContextAttachmentApi)
        self.assertIs(
            sunderkey.TargetContextAttachmentReceipt,
            TargetContextAttachmentReceipt,
        )
        self.assertIs(
            sunderkey.target_context_attachment_capability_manifest,
            target_context_attachment_capability_manifest,
        )


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from sunderkey.orchestration_api import (
    OPENAPI_SHA256,
    ApiPermission,
    OrchestrationApiApp,
    openapi_document,
    openapi_json,
)
from sunderkey.orchestration_journal import (
    ProjectionKind,
    SourceHighWater,
    SQLiteOrchestrationJournal,
    build_read_model_projection,
    canonical_json,
    canonical_sha256,
    loads_json_without_duplicate_keys,
    source_bindings_sha256,
)

T0 = "2026-09-20T12:00:00Z"


def digest(label: str) -> str:
    return canonical_sha256({"label": label})


class Phase197ApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.journal = SQLiteOrchestrationJournal(
            Path(self.temporary.name) / "orchestration.sqlite3",
            trusted_clock=lambda: datetime(2026, 9, 20, 12, 0, 1, tzinfo=UTC),
        )
        self.app = OrchestrationApiApp(self.journal)
        self.source = {
            "observed_at": T0,
            "source_head_sha256": digest("mission-head"),
            "source_id": "mission:alpha",
            "source_kind": "mission_store",
            "source_revision": 1,
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def principal(
        tenant: str = "tenant-a",
        permissions: list[str] | None = None,
        *,
        subject: str = "operator:test",
        authentication: str = "authentication:local-test",
    ):
        return {
            "authentication_context_sha256": digest(authentication),
            "permissions": permissions or sorted(ApiPermission.ALL),
            "subject_id": subject,
            "tenant_id": tenant,
        }

    def request(
        self,
        method: str,
        path: str,
        *,
        body: dict[str, Any] | bytes | None = None,
        query: bytes = b"",
        principal: dict[str, Any] | None = None,
        extra_headers: list[tuple[bytes, bytes]] | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        headers = list(extra_headers or [])
        if body is not None:
            headers.append((b"content-type", b"application/json"))
        payload = canonical_json(body).encode("ascii") if isinstance(body, dict) else body or b""
        scope: dict[str, Any] = {
            "headers": headers,
            "method": method,
            "path": path,
            "query_string": query,
            "type": "http",
        }
        if principal is not None:
            scope["sunderkey.principal"] = principal
        incoming = [{"body": payload, "more_body": False, "type": "http.request"}]
        outgoing: list[dict[str, Any]] = []

        async def receive():
            return incoming.pop(0)

        async def send(message):
            outgoing.append(dict(message))

        asyncio.run(self.app(scope, receive, send))
        start, response = outgoing
        decoded_headers = {
            key.decode("ascii"): value.decode("ascii") for key, value in start["headers"]
        }
        return start["status"], decoded_headers, response["body"]

    def job_body(self, *, tenant: str = "tenant-a", key: str = "job-key") -> dict[str, Any]:
        return {
            "available_at": T0,
            "idempotency_key_sha256": digest(key),
            "input_ref": "snapshot:alpha",
            "input_sha256": digest("snapshot"),
            "job_kind": "source_reconciliation",
            "lease_seconds": 60,
            "maximum_attempts": 3,
            "requested_at": T0,
            "source_bindings": [self.source],
            "subject_ref": "mission:alpha",
            "tenant_id": tenant,
        }

    def handoff_body(
        self, *, tenant: str = "tenant-a", key: str = "action-execution-handoff"
    ) -> dict[str, Any]:
        return {
            "action_execute_intent_sha256": digest("action-execute-intent"),
            "action_execution_envelope_ref": "artifact:phase196/action-execution-request",
            "action_execution_envelope_sha256": digest("action-execution-envelope"),
            "action_execution_request_id": "AXR-0123456789ABCDEF0123456789ABCDEF",
            "action_execution_request_sha256": digest("action-execution-request"),
            "assertion_id": "assertion:action-execute-1",
            "assertion_sha256": digest("action-execute-assertion"),
            "authorization_expires_at": "2026-09-20T12:05:00Z",
            "authorization_sha256": digest("action-execute-authorization"),
            "available_at": T0,
            "command_sha256": digest("action-execution-command"),
            "idempotency_key_sha256": digest(key),
            "mission_id": "mission:alpha",
            "receipt_id": "AARX-0123456789ABCDEF0123456789ABCDEF",
            "receipt_sha256": digest("admission-receipt"),
            "requested_at": T0,
            "source_bindings": [self.source],
            "source_bindings_sha256": source_bindings_sha256(
                (SourceHighWater.from_dict(self.source),)
            ),
            "tenant_id": tenant,
        }

    def test_openapi_is_deterministic_closed_and_available_without_authentication(self) -> None:
        status, headers, body = self.request("GET", "/api/v1/openapi.json")
        self.assertEqual(status, 200)
        self.assertEqual(headers["content-type"], "application/json")
        self.assertEqual(body.decode("ascii"), openapi_json())
        self.assertEqual(digest_from_bytes(body), OPENAPI_SHA256)
        document = openapi_document()
        self.assertEqual(document["openapi"], "3.1.0")
        submit = document["components"]["schemas"]["SubmitJobRequest"]
        self.assertFalse(submit["additionalProperties"])
        self.assertIn("requested_at", submit["required"])
        self.assertNotIn("authoritative_command_handoff", submit["properties"]["job_kind"]["enum"])
        self.assertNotIn("action_execution_handoff", submit["properties"]["job_kind"]["enum"])
        self.assertNotIn("outbox_delivery", submit["properties"]["job_kind"]["enum"])
        self.assertNotIn("/api/v1/operator-actions", document["paths"])
        self.assertIn("/api/v1/action-execution-handoffs", document["paths"])
        self.assertNotIn("OperatorActionEnqueueRequest", document["components"]["schemas"])
        handoff = document["components"]["schemas"]["ActionExecutionHandoffRequest"]
        self.assertFalse(handoff["additionalProperties"])
        self.assertNotIn("authorization", handoff["properties"])
        self.assertNotIn("assertion", handoff["properties"])
        self.assertNotIn("envelope", handoff["properties"])
        for name, schema in document["components"]["schemas"].items():
            with self.subTest(schema=name):
                Draft202012Validator.check_schema(schema)
        response_schema = document["paths"]["/api/v1/jobs"]["post"]["responses"]["202"]["content"][
            "application/json"
        ]["schema"]
        status, _, response = self.request(
            "POST", "/api/v1/jobs", body=self.job_body(), principal=self.principal()
        )
        self.assertEqual(status, 202)
        Draft202012Validator(response_schema).validate(loads_json_without_duplicate_keys(response))

    def test_job_submission_exact_replay_query_and_tenant_isolation(self) -> None:
        body = self.job_body()
        first_status, _, first_raw = self.request(
            "POST", "/api/v1/jobs", body=body, principal=self.principal()
        )
        replay_status, _, replay_raw = self.request(
            "POST", "/api/v1/jobs", body=body, principal=self.principal()
        )
        self.assertEqual((first_status, replay_status), (202, 200))
        first = loads_json_without_duplicate_keys(first_raw)
        replay = loads_json_without_duplicate_keys(replay_raw)
        self.assertFalse(first["replayed"])
        self.assertTrue(replay["replayed"])
        self.assertEqual(first["job"], replay["job"])
        self.assertEqual(first["authority_effect"], "none")
        job_id = first["job"]["job_id"]

        status, _, raw = self.request("GET", f"/api/v1/jobs/{job_id}", principal=self.principal())
        self.assertEqual(status, 200)
        self.assertEqual(loads_json_without_duplicate_keys(raw)["job"]["job_id"], job_id)
        status, _, raw = self.request(
            "GET", "/api/v1/jobs", query=b"limit=10", principal=self.principal()
        )
        self.assertEqual(status, 200)
        self.assertEqual(len(loads_json_without_duplicate_keys(raw)["items"]), 1)
        status, _, _ = self.request(
            "GET", f"/api/v1/jobs/{job_id}", principal=self.principal("tenant-b")
        )
        self.assertEqual(status, 404)

    def test_missing_authentication_and_permission_fail_closed(self) -> None:
        status, _, raw = self.request("GET", "/api/v1/jobs")
        self.assertEqual(status, 401)
        self.assertEqual(
            loads_json_without_duplicate_keys(raw)["error"]["code"],
            "authentication_required",
        )
        status, _, raw = self.request(
            "POST",
            "/api/v1/jobs",
            body=self.job_body(),
            principal=self.principal(permissions=[ApiPermission.JOB_READ]),
        )
        self.assertEqual(status, 403)
        self.assertEqual(
            loads_json_without_duplicate_keys(raw)["error"]["code"], "permission_denied"
        )
        invalid_principal = self.principal()
        invalid_principal["subject_id"] = "operator:../substitute"
        status, _, raw = self.request("GET", "/api/v1/jobs", principal=invalid_principal)
        self.assertEqual(status, 401)
        self.assertEqual(
            loads_json_without_duplicate_keys(raw)["error"]["code"],
            "authentication_required",
        )

    def test_cross_tenant_submission_and_unknown_fields_are_rejected(self) -> None:
        status, _, _ = self.request(
            "POST",
            "/api/v1/jobs",
            body=self.job_body(tenant="tenant-b"),
            principal=self.principal("tenant-a"),
        )
        self.assertEqual(status, 400)
        changed = self.job_body()
        changed["authorize"] = True
        status, _, _ = self.request(
            "POST", "/api/v1/jobs", body=changed, principal=self.principal()
        )
        self.assertEqual(status, 400)

    def test_generic_job_permission_cannot_enqueue_reserved_effect_paths(self) -> None:
        principal = self.principal(permissions=[ApiPermission.JOB_SUBMIT])
        for kind in ("action_execution_handoff", "outbox_delivery"):
            with self.subTest(kind=kind):
                body = self.job_body(key=kind)
                body["job_kind"] = kind
                status, _, raw = self.request(
                    "POST", "/api/v1/jobs", body=body, principal=principal
                )
                self.assertEqual(status, 400)
                self.assertEqual(
                    loads_json_without_duplicate_keys(raw)["error"]["code"],
                    "invalid_request",
                )
        handoff_body = self.handoff_body(key="restricted-action-execution")
        status, _, _ = self.request(
            "POST",
            "/api/v1/action-execution-handoffs",
            body=handoff_body,
            principal=principal,
        )
        self.assertEqual(status, 403)
        self.assertEqual(self.journal.verify()["counts"]["jobs"], 0)
        malformed = self.job_body(key="malformed-kind")
        malformed["job_kind"] = ["action_execution_handoff"]
        status, _, raw = self.request("POST", "/api/v1/jobs", body=malformed, principal=principal)
        self.assertEqual(status, 400)
        self.assertEqual(loads_json_without_duplicate_keys(raw)["error"]["code"], "invalid_request")

    def test_duplicate_json_keys_are_rejected(self) -> None:
        payload = b'{"tenant_id":"tenant-a","tenant_id":"tenant-a"}'
        status, _, raw = self.request(
            "POST", "/api/v1/jobs", body=payload, principal=self.principal()
        )
        self.assertEqual(status, 400)
        self.assertEqual(loads_json_without_duplicate_keys(raw)["error"]["code"], "invalid_request")

    def test_action_execution_handoff_only_stages_content_addressed_envelope(self) -> None:
        body = self.handoff_body()
        body["available_at"] = "2026-09-20T12:04:00Z"
        first_status, first_headers, first_raw = self.request(
            "POST",
            "/api/v1/action-execution-handoffs",
            body=body,
            principal=self.principal(),
        )
        replay_status, _, replay_raw = self.request(
            "POST",
            "/api/v1/action-execution-handoffs",
            body=body,
            principal=self.principal(),
        )
        self.assertEqual((first_status, replay_status), (202, 200))
        self.assertEqual(first_headers["cache-control"], "no-store")
        first = loads_json_without_duplicate_keys(first_raw)
        replay = loads_json_without_duplicate_keys(replay_raw)
        self.assertEqual(first["authority_effect"], "none")
        self.assertTrue(first["authoritative_reverification_required"])
        self.assertEqual(first["status"], "staged_for_authenticated_action_execution_handoff")
        self.assertTrue(replay["replayed"])
        self.assertEqual(first["job"]["subject_ref"], first["message"]["message_id"])
        self.assertEqual(first["job"]["maximum_attempts"], 1)
        self.assertEqual(first["job"]["input_ref"], first["intent"]["intent_id"])
        self.assertEqual(first["job"]["input_sha256"], first["intent"]["intent_sha256"])
        self.assertEqual(first["intent"]["requested_by_subject_id"], "operator:test")
        self.assertEqual(
            first["intent"]["authentication_context_sha256"],
            self.principal()["authentication_context_sha256"],
        )
        self.assertEqual(first["intent"]["requested_at"], T0)
        self.assertEqual(first["intent"]["available_at"], "2026-09-20T12:04:00Z")
        self.assertEqual(first["job"]["created_at"], "2026-09-20T12:00:01Z")
        self.assertEqual(first["job"]["available_at"], "2026-09-20T12:04:00Z")
        self.assertEqual(
            first["message"]["external_ref"], body["action_execution_envelope_ref"]
        )
        self.assertEqual(first["message"]["correlation_ref"], body["action_execution_request_id"])
        self.assertEqual(self.journal.verify()["counts"]["messages"], 1)

        changed_principal = self.principal(
            subject="operator:substitute", authentication="authentication:substitute"
        )
        status, _, raw = self.request(
            "POST",
            "/api/v1/action-execution-handoffs",
            body=body,
            principal=changed_principal,
        )
        self.assertEqual(status, 409)
        self.assertEqual(loads_json_without_duplicate_keys(raw)["error"]["code"], "conflict")

    def test_action_execution_handoff_rejects_inline_material_and_binding_drift(self) -> None:
        for forbidden in (
            "adapter_input",
            "api_key",
            "assertion",
            "authorization",
            "credentials",
            "envelope",
            "raw_evidence",
            "token",
        ):
            with self.subTest(forbidden=forbidden):
                body = self.handoff_body(key=f"forbidden-{forbidden}")
                body[forbidden] = {"material": "must-not-cross-the-api"}
                payload = json.dumps(body, separators=(",", ":"), sort_keys=True).encode("ascii")
                status, headers, raw = self.request(
                    "POST",
                    "/api/v1/action-execution-handoffs",
                    body=payload,
                    principal=self.principal(),
                )
                self.assertEqual(status, 400)
                self.assertEqual(headers["cache-control"], "no-store")
                self.assertEqual(
                    loads_json_without_duplicate_keys(raw)["error"]["code"],
                    "invalid_request",
                )

        cross_tenant = self.handoff_body(tenant="tenant-b", key="cross-tenant")
        status, _, _ = self.request(
            "POST",
            "/api/v1/action-execution-handoffs",
            body=cross_tenant,
            principal=self.principal("tenant-a"),
        )
        self.assertEqual(status, 400)
        drifted = self.handoff_body(key="drifted-source-vector")
        drifted["source_bindings_sha256"] = digest("different-source-vector")
        status, _, _ = self.request(
            "POST",
            "/api/v1/action-execution-handoffs",
            body=drifted,
            principal=self.principal(),
        )
        self.assertEqual(status, 400)
        raw_token = self.handoff_body(key="raw-token")
        raw_token["action_execution_envelope_ref"] = (
            "eyJ0123456789.eyJ0123456789.abcdefghijklmnopqrstuvwxyz"
        )
        status, _, _ = self.request(
            "POST",
            "/api/v1/action-execution-handoffs",
            body=json.dumps(raw_token, separators=(",", ":"), sort_keys=True).encode("ascii"),
            principal=self.principal(),
        )
        self.assertEqual(status, 400)
        expiring = self.handoff_body(key="insufficient-authorization-window")
        expiring["authorization_expires_at"] = "2026-09-20T12:00:05Z"
        status, _, _ = self.request(
            "POST",
            "/api/v1/action-execution-handoffs",
            body=expiring,
            principal=self.principal(),
        )
        self.assertEqual(status, 409)
        self.assertEqual(self.journal.verify()["counts"]["jobs"], 0)

    def test_old_operator_and_worker_mutation_surfaces_are_absent(self) -> None:
        document = openapi_document()
        self.assertEqual(
            set(document["paths"]),
            {
                "/api/v1/action-execution-handoffs",
                "/api/v1/events",
                "/api/v1/jobs",
                "/api/v1/jobs/{job_id}",
                "/api/v1/openapi.json",
                "/api/v1/projections/{projection_kind}/{subject_ref}",
            },
        )
        for path in (
            "/api/v1/operator-actions",
            "/api/v1/jobs/JOB-0123456789ABCDEF0123456789ABCDEF/claim",
            "/api/v1/jobs/JOB-0123456789ABCDEF0123456789ABCDEF/outcome",
            "/api/v1/reconciliation",
        ):
            with self.subTest(path=path):
                status, headers, raw = self.request(
                    "POST", path, body={}, principal=self.principal()
                )
                self.assertEqual(status, 404)
                self.assertEqual(headers["cache-control"], "no-store")
                self.assertEqual(
                    loads_json_without_duplicate_keys(raw)["error"]["code"], "not_found"
                )
        stale_permission = self.principal(
            permissions=["orchestration.operator_actions.enqueue"]
        )
        status, _, raw = self.request("GET", "/api/v1/jobs", principal=stale_permission)
        self.assertEqual(status, 401)
        self.assertEqual(
            loads_json_without_duplicate_keys(raw)["error"]["code"],
            "authentication_required",
        )

    def test_projection_response_is_explicitly_non_authoritative(self) -> None:
        source = SourceHighWater.from_dict(self.source)
        projection = build_read_model_projection(
            tenant_id="tenant-a",
            projection_kind=ProjectionKind.MISSION,
            subject_ref="mission:alpha",
            projection_version=1,
            source_bindings=(source,),
            payload={"state": "observed_active"},
            projected_at=T0,
        )
        self.journal.reconcile_projection(projection)
        status, _, raw = self.request(
            "GET",
            "/api/v1/projections/mission/mission:alpha",
            principal=self.principal(),
        )
        self.assertEqual(status, 200)
        response = loads_json_without_duplicate_keys(raw)
        self.assertFalse(response["authoritative"])
        self.assertTrue(response["source_reconciliation_required_for_decisions"])
        self.assertEqual(response["projection"], projection.to_dict())

    def test_projection_subject_with_slash_remains_addressable(self) -> None:
        source = SourceHighWater.from_dict(self.source)
        projection = build_read_model_projection(
            tenant_id="tenant-a",
            projection_kind=ProjectionKind.MISSION,
            subject_ref="mission:group/alpha",
            projection_version=1,
            source_bindings=(source,),
            payload={"state": "observed_active"},
            projected_at=T0,
        )
        self.journal.reconcile_projection(projection)
        status, headers, raw = self.request(
            "GET",
            "/api/v1/projections/mission/mission:group/alpha",
            principal=self.principal(),
        )
        self.assertEqual(status, 200)
        self.assertEqual(headers["cache-control"], "no-store")
        self.assertEqual(
            loads_json_without_duplicate_keys(raw)["projection"]["subject_ref"],
            "mission:group/alpha",
        )

    def test_sse_resumes_after_last_event_id_and_is_tenant_scoped(self) -> None:
        self.request("POST", "/api/v1/jobs", body=self.job_body(), principal=self.principal())
        status, headers, body = self.request(
            "GET", "/api/v1/events", query=b"limit=10", principal=self.principal()
        )
        self.assertEqual(status, 200)
        self.assertEqual(headers["content-type"], "text/event-stream; charset=utf-8")
        text = body.decode("ascii")
        first_event_id = next(
            line.removeprefix("id: ") for line in text.splitlines() if line.startswith("id: ")
        )
        self.assertRegex(first_event_id, r"^JEV-[0-9A-F]{32}$")
        self.assertIn("event: job.submitted\n", text)
        status, _, body = self.request(
            "GET",
            "/api/v1/events",
            principal=self.principal(),
            extra_headers=[(b"last-event-id", first_event_id.encode("ascii"))],
        )
        self.assertEqual(status, 200)
        self.assertEqual(body, b": no-new-events\n\n")
        self.request(
            "POST",
            "/api/v1/jobs",
            body=self.job_body(tenant="tenant-b", key="tenant-b-job"),
            principal=self.principal("tenant-b"),
        )
        self.request(
            "POST",
            "/api/v1/jobs",
            body=self.job_body(key="tenant-a-second"),
            principal=self.principal(),
        )
        status, _, body = self.request(
            "GET",
            "/api/v1/events",
            principal=self.principal(),
            extra_headers=[(b"last-event-id", first_event_id.encode("ascii"))],
        )
        self.assertEqual(status, 200)
        self.assertNotEqual(body, b": no-new-events\n\n")
        self.assertNotIn(b"tenant-b", body)
        status, _, body = self.request(
            "GET", "/api/v1/events", principal=self.principal("tenant-b")
        )
        self.assertEqual(status, 200)
        tenant_b_id = next(
            line.removeprefix(b"id: ") for line in body.splitlines() if line.startswith(b"id: ")
        )
        self.assertNotIn(b"tenant-a", body)
        status, _, raw = self.request(
            "GET",
            "/api/v1/events",
            principal=self.principal(),
            extra_headers=[(b"last-event-id", tenant_b_id)],
        )
        self.assertEqual(status, 400)
        self.assertEqual(
            loads_json_without_duplicate_keys(raw)["error"]["code"],
            "invalid_event_cursor",
        )

    def test_invalid_sse_cursor_and_oversized_body_fail_closed(self) -> None:
        status, _, _ = self.request(
            "GET",
            "/api/v1/events",
            principal=self.principal(),
            extra_headers=[(b"last-event-id", b"not-an-event-id")],
        )
        self.assertEqual(status, 400)
        status, _, _ = self.request(
            "GET",
            "/api/v1/events",
            principal=self.principal(),
            extra_headers=[(b"last-event-id", b"JEV-" + b"0" * 32)],
        )
        self.assertEqual(status, 400)
        status, _, raw = self.request(
            "POST", "/api/v1/jobs", body=b"{" + b"x" * 131_072, principal=self.principal()
        )
        self.assertEqual(status, 413)
        self.assertEqual(loads_json_without_duplicate_keys(raw)["error"]["code"], "body_too_large")

    def test_deep_json_and_excessive_query_fields_fail_closed(self) -> None:
        deeply_nested = b'{"nested":' + (b"[" * 2_000) + (b"]" * 2_000) + b"}"
        status, _, raw = self.request(
            "POST", "/api/v1/jobs", body=deeply_nested, principal=self.principal()
        )
        self.assertEqual(status, 400)
        self.assertEqual(loads_json_without_duplicate_keys(raw)["error"]["code"], "invalid_request")

        query = b"&".join(f"field{index}=x".encode("ascii") for index in range(65))
        status, _, raw = self.request(
            "GET", "/api/v1/jobs", query=query, principal=self.principal()
        )
        self.assertEqual(status, 400)
        self.assertEqual(loads_json_without_duplicate_keys(raw)["error"]["code"], "invalid_request")

    def test_invalid_asgi_metadata_and_receive_frame_fail_closed(self) -> None:
        for method, path in (("GET\n", "/api/v1/jobs"), ("GET", "/" + "x" * 2048)):
            with self.subTest(method=method, path_length=len(path)):
                status, _, raw = self.request(method, path, principal=self.principal())
                self.assertEqual(status, 400)
                self.assertEqual(
                    loads_json_without_duplicate_keys(raw)["error"]["code"],
                    "invalid_request",
                )

        outgoing: list[dict[str, Any]] = []

        async def receive():
            return []

        async def send(message):
            outgoing.append(dict(message))

        scope = {
            "headers": [(b"content-type", b"application/json")],
            "method": "POST",
            "path": "/api/v1/jobs",
            "query_string": b"",
            "sunderkey.principal": self.principal(),
            "type": "http",
        }
        asyncio.run(self.app(scope, receive, send))
        self.assertEqual(outgoing[0]["status"], 400)
        self.assertEqual(
            loads_json_without_duplicate_keys(outgoing[1]["body"])["error"]["code"],
            "invalid_request",
        )


def digest_from_bytes(value: bytes) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(value).hexdigest()


if __name__ == "__main__":
    unittest.main()

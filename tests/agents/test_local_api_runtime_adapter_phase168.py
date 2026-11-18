import asyncio
import hashlib
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from jsonschema import Draft202012Validator

from sunderkey.local_api_runtime_adapter import (
    ASGI_PATH,
    MAX_BODY_BYTES,
    SQLITE_MIGRATION_ID,
    SQLITE_MIGRATION_SHA256,
    LocalApiAsgiApp,
    MigrationIdentityError,
    RepositoryIntegrityError,
    SQLiteServiceRepository,
    _service_request,
    runtime_adapter_manifest,
)
from sunderkey.local_api_service import (
    AccessCheck,
    AccessDecision,
    AdmissionStatus,
    DecisionStatus,
    MutationAdmission,
    MutationCheck,
    Operation,
    ResourceKind,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "registry" / "schemas" / "local-api-runtime-adapter-v1.schema.json"
NOW = "2026-09-20T12:00:00Z"


class BoundAuthorizer:
    def authorize(self, check: AccessCheck) -> AccessDecision:
        return AccessDecision(
            decision_ref="authzref:local-api-runtime",
            status=DecisionStatus.ALLOWED,
            request_sha256=check.request_sha256,
            tenant_id=check.tenant_id,
            context_id=check.context_id,
            principal_id=check.principal_id,
            session_ref=check.session_ref,
            permission=check.permission,
            valid_through="2027-09-20T12:00:00Z",
            audit_ref="auditref:local-api-authorization",
        )


class BoundAdmitter:
    def admit(self, check: MutationCheck) -> MutationAdmission:
        return MutationAdmission(
            admission_ref="admitref:local-api-runtime",
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
            valid_through="2027-09-20T12:00:00Z",
            audit_ref="auditref:local-api-admission",
        )


def access(tenant: str = "tenant-a", context: str = "context-red") -> dict:
    return {
        "context_id": context,
        "principal_id": "principal-operator",
        "session_ref": "session-verified",
        "tenant_id": tenant,
    }


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


def create_request(
    resource_id: str,
    *,
    tenant: str = "tenant-a",
    context: str = "context-red",
    request_id: str | None = None,
) -> dict:
    return {
        "access": access(tenant, context),
        "idempotency_key": f"idem:create-{tenant}-{context}-{resource_id}-0001",
        "operation": Operation.CREATE_ASSET.value,
        "payload": asset_payload(resource_id),
        "request_id": request_id or f"request-create-{resource_id}",
        "requested_at": NOW,
        "resource_id": resource_id,
        "resource_kind": ResourceKind.ASSET.value,
    }


def get_request(
    resource_id: str,
    *,
    tenant: str = "tenant-a",
    context: str = "context-red",
) -> dict:
    return {
        "access": access(tenant, context),
        "operation": Operation.GET_RESOURCE.value,
        "request_id": f"request-get-{resource_id}",
        "requested_at": NOW,
        "resource_id": resource_id,
        "resource_kind": ResourceKind.ASSET.value,
    }


def list_request(
    *,
    tenant: str = "tenant-a",
    context: str = "context-red",
    cursor: str | None = None,
    page_size: int = 10,
) -> dict:
    request = {
        "access": access(tenant, context),
        "operation": Operation.LIST_RESOURCES.value,
        "page_size": page_size,
        "request_id": "request-list-assets",
        "requested_at": NOW,
        "resource_kind": ResourceKind.ASSET.value,
    }
    if cursor is not None:
        request["cursor"] = cursor
    return request


async def invoke(
    app: LocalApiAsgiApp,
    document: dict | bytes,
    *,
    headers: tuple[tuple[bytes, bytes], ...] | None = None,
    method: str = "POST",
    path: str = ASGI_PATH,
) -> tuple[int, dict, dict[str, str]]:
    body = document if isinstance(document, bytes) else json.dumps(document).encode("utf-8")
    messages = [{"body": body, "more_body": False, "type": "http.request"}]
    sent: list[dict] = []

    async def receive() -> dict:
        return messages.pop(0)

    async def send(message: dict) -> None:
        sent.append(message)

    await app(
        {
            "headers": headers or ((b"content-type", b"application/json"),),
            "http_version": "1.1",
            "method": method,
            "path": path,
            "query_string": b"",
            "type": "http",
        },
        receive,
        send,
    )
    response_headers = {
        name.decode("ascii"): value.decode("ascii") for name, value in sent[0]["headers"]
    }
    return sent[0]["status"], json.loads(sent[1]["body"]), response_headers


class LocalApiRuntimeAdapterPhase168Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.database = Path(self.temporary.name) / "runtime.sqlite3"
        self.repository = SQLiteServiceRepository(self.database)
        self.app = LocalApiAsgiApp(self.repository, BoundAuthorizer(), BoundAdmitter())

    def call(self, document: dict | bytes, **kwargs):
        return asyncio.run(invoke(self.app, document, **kwargs))

    def test_manifest_is_explicit_about_local_effects_and_external_controls(self) -> None:
        manifest = runtime_adapter_manifest()
        self.assertEqual(manifest["migration"]["migration_id"], SQLITE_MIGRATION_ID)
        self.assertEqual(manifest["migration"]["migration_sha256"], SQLITE_MIGRATION_SHA256)
        self.assertEqual(manifest["effects"]["network_listener"], "none")
        self.assertEqual(manifest["effects"]["authentication"], "injected_authorizer_only")
        self.assertEqual(manifest["effects"]["target_actions"], "none")
        self.assertEqual(manifest["effects"]["production_qualification"], "none")

    def test_asgi_create_replay_and_restart_preserve_one_atomic_result(self) -> None:
        request = create_request("asset-restart")
        status, first, headers = self.call(
            request,
            headers=(
                (b"content-type", b"application/json"),
                (b"x-correlation-id", b"corr-client-001"),
            ),
        )
        self.assertEqual(status, 200)
        self.assertEqual(first["data"]["status"], "completed")
        self.assertEqual(first["correlation_id"], "corr-client-001")
        self.assertEqual(headers["cache-control"], "no-store")
        reopened = SQLiteServiceRepository(self.database)
        self.app = LocalApiAsgiApp(reopened, BoundAuthorizer(), BoundAdmitter())
        status, replay, _ = self.call(request)
        self.assertEqual(status, 200)
        self.assertEqual(replay["data"]["status"], "replayed")
        self.assertEqual(replay["data"]["resource"], first["data"]["resource"])
        self.assertEqual(reopened.verify_integrity()["resources"], 1)
        self.assertEqual(reopened.verify_integrity()["audit_entries"], 1)
        self.assertEqual(reopened.verify_integrity()["integration_events"], 1)
        self.assertEqual(reopened.verify_integrity()["idempotency_results"], 1)

    def test_optimistic_update_appends_audit_and_stale_update_fails(self) -> None:
        _, created, _ = self.call(create_request("asset-update"))
        token = created["data"]["resource"]["concurrency_token"]
        update = {
            "access": access(),
            "expected_concurrency_token": token,
            "idempotency_key": "idem:update-asset-update-00000001",
            "operation": Operation.UPDATE_ASSET.value,
            "payload": asset_payload("Updated API"),
            "request_id": "request-update-asset",
            "requested_at": NOW,
            "resource_id": "asset-update",
            "resource_kind": ResourceKind.ASSET.value,
        }
        status, updated, _ = self.call(update)
        self.assertEqual(status, 200)
        self.assertEqual(updated["data"]["resource"]["version"], 2)
        self.assertEqual(len(updated["data"]["resource"]["audit_refs"]), 2)
        update["idempotency_key"] = "idem:update-asset-update-00000002"
        update["request_id"] = "request-update-stale"
        status, error, _ = self.call(update)
        self.assertEqual(status, 409)
        self.assertEqual(error["error"]["code"], "state_conflict")
        self.assertEqual(self.repository.verify_integrity()["audit_entries"], 2)

    def test_stable_pagination_and_tenant_context_isolation_survive_restart(self) -> None:
        for resource_id in ("asset-c", "asset-a", "asset-b"):
            self.assertEqual(self.call(create_request(resource_id))[0], 200)
        self.assertEqual(
            self.call(create_request("asset-a", tenant="tenant-b", context="context-blue"))[0],
            200,
        )
        status, first, _ = self.call(list_request(page_size=2))
        self.assertEqual(status, 200)
        self.assertEqual(
            [item["resource_id"] for item in first["data"]["page"]["items"]],
            ["asset-a", "asset-b"],
        )
        cursor = first["data"]["page"]["next_cursor"]
        self.app = LocalApiAsgiApp(
            SQLiteServiceRepository(self.database), BoundAuthorizer(), BoundAdmitter()
        )
        status, second, _ = self.call(list_request(cursor=cursor, page_size=2))
        self.assertEqual(status, 200)
        self.assertEqual(
            [item["resource_id"] for item in second["data"]["page"]["items"]],
            ["asset-c"],
        )
        status, isolated, _ = self.call(
            list_request(tenant="tenant-b", context="context-blue", page_size=10)
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            [item["resource_id"] for item in isolated["data"]["page"]["items"]],
            ["asset-a"],
        )
        status, absent, _ = self.call(get_request("asset-c", tenant="tenant-b"))
        self.assertEqual(status, 404)
        self.assertEqual(absent["error"]["code"], "resource_not_found")

    def test_failed_event_insert_rolls_back_resource_audit_and_idempotency(self) -> None:
        connection = sqlite3.connect(self.database)
        try:
            connection.execute(
                "CREATE TRIGGER reject_event BEFORE INSERT ON integration_events "
                "BEGIN SELECT RAISE(ABORT, 'event rejected'); END"
            )
            connection.commit()
        finally:
            connection.close()
        status, error, _ = self.call(create_request("asset-rollback"))
        self.assertEqual(status, 500)
        self.assertEqual(error["error"]["code"], "internal_error")
        counts = self.repository.verify_integrity()
        self.assertEqual(counts["resources"], 0)
        self.assertEqual(counts["audit_entries"], 0)
        self.assertEqual(counts["integration_events"], 0)
        self.assertEqual(counts["idempotency_results"], 0)

    def test_wire_boundary_rejects_credentials_paths_limits_and_wrong_media(self) -> None:
        credential = create_request("asset-credential")
        credential["payload"]["secret"] = "not-accepted"
        status, body, _ = self.call(credential)
        self.assertEqual((status, body["error"]["code"]), (400, "credential_value_rejected"))
        path_value = create_request("asset-path")
        path_value["payload"]["name"] = "C:\\sensitive\\file.txt"
        status, body, _ = self.call(path_value)
        self.assertEqual((status, body["error"]["code"]), (400, "filesystem_path_rejected"))
        status, body, _ = self.call(
            create_request("asset-header"),
            headers=(
                (b"content-type", b"application/json"),
                (b"authorization", b"Bearer value"),
            ),
        )
        self.assertEqual((status, body["error"]["code"]), (400, "credential_transport_rejected"))
        status, body, _ = self.call(
            create_request("asset-media"), headers=((b"content-type", b"text/plain"),)
        )
        self.assertEqual((status, body["error"]["code"]), (415, "unsupported_media_type"))
        status, body, _ = self.call(b"{" + b"x" * MAX_BODY_BYTES + b"}")
        self.assertEqual((status, body["error"]["code"]), (413, "body_too_large"))
        status, body, _ = self.call(list_request(page_size=101))
        self.assertEqual((status, body["error"]["code"]), (400, "page_limit_exceeded"))

    def test_errors_are_normalized_and_do_not_echo_sensitive_input(self) -> None:
        status, body, headers = self.call(b'{"password":"do-not-echo"}')
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "credential_value_rejected")
        self.assertNotIn("do-not-echo", json.dumps(body))
        self.assertTrue(body["correlation_id"].startswith("corr:"))
        self.assertEqual(headers["x-correlation-id"], body["correlation_id"])

    def test_migration_identity_tamper_fails_reopen_closed(self) -> None:
        connection = sqlite3.connect(self.database)
        try:
            connection.execute(
                "UPDATE schema_migrations SET migration_sha256=? WHERE version=1",
                ("sha256:" + "0" * 64,),
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(RepositoryIntegrityError):
            self.repository.verify_integrity()
        with self.assertRaises(MigrationIdentityError):
            SQLiteServiceRepository(self.database)

    def test_persisted_audit_chain_link_tamper_is_detected(self) -> None:
        _, created, _ = self.call(create_request("asset-chain"))
        update = {
            "access": access(),
            "expected_concurrency_token": created["data"]["resource"]["concurrency_token"],
            "idempotency_key": "idem:update-asset-chain-000000001",
            "operation": Operation.UPDATE_ASSET.value,
            "payload": asset_payload("Updated chain"),
            "request_id": "request-update-chain",
            "requested_at": NOW,
            "resource_id": "asset-chain",
            "resource_kind": ResourceKind.ASSET.value,
        }
        self.assertEqual(self.call(update)[0], 200)
        connection = sqlite3.connect(self.database)
        try:
            connection.execute(
                "UPDATE audit_entries SET prior_audit_ref=NULL WHERE resource_version=2"
            )
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(RepositoryIntegrityError):
            self.repository.verify_integrity()

    def test_store_integrity_rejects_sql_metadata_substitution(self) -> None:
        self.assertEqual(self.call(create_request("asset-metadata"))[0], 200)
        cases = (
            ("resources", "tenant_id", "tenant-other", "tenant-a"),
            ("audit_entries", "tenant_id", "tenant-other", "tenant-a"),
            ("integration_events", "tenant_id", "tenant-other", "tenant-a"),
            ("idempotency_results", "tenant_id", "tenant-other", "tenant-a"),
            ("resources", "version", 2, 1),
            ("audit_entries", "resource_version", 2, 1),
            ("integration_events", "resource_version", 2, 1),
            ("idempotency_results", "request_sha256", "sha256:" + "0" * 64, None),
            ("resources", "resource_json", b"not-native-text", None),
        )
        for table, column, changed, original in cases:
            with self.subTest(table=table, column=column):
                with closing(sqlite3.connect(self.database)) as connection, connection:
                    if original is None:
                        original = connection.execute(
                            f"SELECT {column} FROM {table}"
                        ).fetchone()[0]
                    connection.execute(f"UPDATE {table} SET {column}=?", (changed,))
                with self.assertRaises(RepositoryIntegrityError):
                    self.repository.verify_integrity()
                with closing(sqlite3.connect(self.database)) as connection, connection:
                    connection.execute(f"UPDATE {table} SET {column}=?", (original,))
                self.assertEqual(self.repository.verify_integrity()["resources"], 1)

    def test_store_integrity_rejects_missing_historical_event(self) -> None:
        self.assertEqual(self.call(create_request("asset-history"))[0], 200)
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute("DELETE FROM integration_events")
        with self.assertRaises(RepositoryIntegrityError):
            self.repository.verify_integrity()

    def test_store_integrity_rejects_missing_historical_result(self) -> None:
        self.assertEqual(self.call(create_request("asset-history"))[0], 200)
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute("DELETE FROM idempotency_results")
        with self.assertRaises(RepositoryIntegrityError):
            self.repository.verify_integrity()

    def test_repository_reads_reject_inconsistent_sql_rows(self) -> None:
        request = create_request("asset-read-boundary")
        self.assertEqual(self.call(request)[0], 200)
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute("UPDATE resources SET version=2")
        with self.assertRaises(RepositoryIntegrityError):
            self.repository.get(
                ResourceKind.ASSET, "tenant-a", "context-red", "asset-read-boundary"
            )
        with self.assertRaises(RepositoryIntegrityError):
            self.repository.list_after(ResourceKind.ASSET, "tenant-a", "context-red", None, 2)
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute("UPDATE resources SET version=1")
            connection.execute(
                "UPDATE idempotency_results SET request_sha256=?",
                ("sha256:" + "0" * 64,),
            )
        with self.assertRaises(RepositoryIntegrityError):
            self.repository.lookup_idempotency(
                "tenant-a", "context-red", _service_request(request).idempotency_sha256
            )

    def test_store_integrity_rejects_discarded_or_duplicate_row_fields(self) -> None:
        self.assertEqual(self.call(create_request("asset-row-json"))[0], 200)
        cases = (
            ("resources", "resource_json", "resource_sha256"),
            ("audit_entries", "entry_json", "entry_sha256"),
            ("integration_events", "event_json", "event_sha256"),
        )
        for table, content_column, digest_column in cases:
            with closing(sqlite3.connect(self.database)) as connection:
                original, digest = connection.execute(
                    f"SELECT {content_column},{digest_column} FROM {table}"
                ).fetchone()
            added = {**json.loads(original), "unexpected": "discarded"}
            for changed in (
                json.dumps(added, sort_keys=True, separators=(",", ":")),
                '{"tenant_id":"tenant-other",' + original[1:],
            ):
                with self.subTest(table=table, duplicate="unexpected" not in changed):
                    changed_digest = "sha256:" + hashlib.sha256(
                        changed.encode("utf-8")
                    ).hexdigest()
                    with closing(sqlite3.connect(self.database)) as connection, connection:
                        connection.execute(
                            f"UPDATE {table} SET {content_column}=?,{digest_column}=?",
                            (changed, changed_digest),
                        )
                    with self.assertRaises(RepositoryIntegrityError):
                        self.repository.verify_integrity()
                    with closing(sqlite3.connect(self.database)) as connection, connection:
                        connection.execute(
                            f"UPDATE {table} SET {content_column}=?,{digest_column}=?",
                            (original, digest),
                        )
                    self.assertEqual(self.repository.verify_integrity()["resources"], 1)

    def test_schema_accepts_request_success_error_and_rejects_unknown_fields(self) -> None:
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        request = create_request("asset-schema")
        validator.validate(request)
        _, success, _ = self.call(request)
        validator.validate(success)
        _, error, _ = self.call(b"not-json")
        validator.validate(error)
        tampered = dict(success)
        tampered["unexpected"] = True
        self.assertTrue(list(validator.iter_errors(tampered)))

    def test_public_symbols_are_available_without_runtime_effects(self) -> None:
        import sunderkey.local_api_runtime_adapter as module

        expected = {
            "ASGI_PATH",
            "LocalApiAsgiApp",
            "LocalApiRuntimeError",
            "MigrationIdentityError",
            "RepositoryBusy",
            "RepositoryConflict",
            "RepositoryIntegrityError",
            "SQLiteServiceRepository",
            "runtime_adapter_manifest",
        }
        self.assertTrue(expected.issubset(set(dir(module))))

    def test_public_package_exports_runtime_adapter(self) -> None:
        import sunderkey

        self.assertIs(sunderkey.LocalApiAsgiApp, LocalApiAsgiApp)
        self.assertIs(sunderkey.SQLiteServiceRepository, SQLiteServiceRepository)
        self.assertIs(sunderkey.local_api_runtime_adapter_manifest, runtime_adapter_manifest)
        self.assertEqual(sunderkey.LOCAL_API_ASGI_PATH, ASGI_PATH)


if __name__ == "__main__":
    unittest.main()

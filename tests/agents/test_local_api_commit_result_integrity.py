from __future__ import annotations

import copy
import hashlib
import json
import unittest
from contextlib import contextmanager
from dataclasses import replace
from unittest import mock

from sunderkey.local_api_runtime_adapter import (
    LocalApiAsgiApp,
    RepositoryIntegrityError,
    SQLiteServiceRepository,
    _result_document,
    _result_from_json,
    _service_request,
    _validate_commit_command,
)
from sunderkey.local_api_service import (
    CommitResult,
    LocalApiServiceError,
    Operation,
    _concurrency_token,
    _validate_commit_result,
    canonical_sha256,
)
from tests.agents import test_local_api_runtime_adapter_phase168 as fixtures


class LocalApiCommitResultIntegrityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = fixtures.LocalApiRuntimeAdapterPhase168Tests(methodName="runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.request = fixtures.create_request("asset-integrity")
        status, self.created, _ = self.fixture.call(self.request)
        self.assertEqual(status, 200)
        self.typed_request = _service_request(self.request)
        self.original = self.fixture.repository.lookup_idempotency(
            "tenant-a", "context-red", self.typed_request.idempotency_sha256
        )
        self.assertIsNotNone(self.original)
        self.document = _result_document(self.original)

    def changed(self, section: str, field: str, value):
        document = copy.deepcopy(self.document)
        document[section][field] = value
        return document

    def read_replay(self, document, request=None):
        text = json.dumps(document, sort_keys=True, separators=(",", ":"))
        row = {
            "tenant_id": self.original.record.tenant_id,
            "context_id": self.original.record.context_id,
            "idempotency_sha256": self.original.idempotency_sha256,
            "request_sha256": self.original.request_sha256,
            "result_json": text,
            "result_sha256": "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest(),
        }

        class Connection:
            def execute(self, query, parameters):
                return self

            def fetchone(self):
                return row

        @contextmanager
        def source_read():
            yield Connection()

        original_lookup = self.fixture.repository.lookup_idempotency

        def lookup(*args):
            with mock.patch.object(self.fixture.repository, "_read", side_effect=source_read):
                return original_lookup(*args)

        with mock.patch.object(self.fixture.repository, "lookup_idempotency", side_effect=lookup):
            return self.fixture.call(self.request if request is None else request)

    def update_request(self):
        return {
            **fixtures.create_request("asset-integrity"),
            "request_id": "request-update-integrity",
            "operation": Operation.UPDATE_ASSET.value,
            "payload": fixtures.asset_payload("Updated resource"),
            "expected_concurrency_token": self.original.record.concurrency_token,
            "idempotency_key": "idem:update-integrity-00000001",
            "requested_at": "2026-09-20T12:00:01Z",
        }

    @staticmethod
    def readdress_event(event, record, **changes):
        event = replace(event, resource_sha256=canonical_sha256(record.to_dict()), **changes)
        return replace(
            event,
            event_id="event:"
            + canonical_sha256(
                {
                    "audit_ref": event.audit_ref,
                    "event_type": event.event_type,
                    "resource_sha256": event.resource_sha256,
                }
            )[7:],
        )

    def test_native_event_and_audit_contradictions_fail_real_hash_read_and_asgi(self) -> None:
        cases = (
            ("audit_entry", "request_sha256", "sha256:" + "0" * 64),
            ("audit_entry", "resource_id", "asset-other"),
            ("audit_entry", "tenant_id", "tenant-other"),
            ("audit_entry", "context_id", "context-other"),
            ("audit_entry", "resulting_concurrency_token", "ct:" + "0" * 64),
            ("audit_entry", "recorded_at", "2026-09-20T12:00:01Z"),
            ("audit_entry", "resource_kind", "finding"),
            ("audit_entry", "audit_ref", "auditref:unrelated"),
            ("audit_entry", "authorization_ref", "authzref:unrelated"),
            ("audit_entry", "admission_ref", "admitref:unrelated"),
            ("audit_entry", "admission_audit_ref", "not-an-audit-ref"),
            ("audit_entry", "principal_id", "invalid principal"),
            ("integration_event", "resource_id", "asset-other"),
            ("integration_event", "tenant_id", "tenant-other"),
            ("integration_event", "context_id", "context-other"),
            ("integration_event", "resource_kind", "finding"),
            ("integration_event", "resource_version", 2),
            ("integration_event", "resource_version", True),
            ("integration_event", "resource_version", 1.0),
            ("integration_event", "event_id", "event:" + "0" * 64),
            ("integration_event", "event_type", "asset.update_asset"),
            ("integration_event", "occurred_at", "2026-09-20T12:00:01Z"),
            ("integration_event", "resource_sha256", "sha256:" + "0" * 64),
            ("integration_event", "audit_ref", "auditref:unrelated"),
            ("record", "version", True),
            ("record", "version", 1.0),
            ("record", "created_at", "2026-09-20T11:59:59Z"),
        )
        for section, field, value in cases:
            with self.subTest(section=section, field=field, value=value):
                status, response, _ = self.read_replay(self.changed(section, field, value))
                self.assertNotEqual(status, 200)
                self.assertNotIn("data", response)
        self.assertEqual(self.fixture.repository.verify_integrity()["idempotency_results"], 1)

    def test_unknown_duplicate_and_aliased_persisted_fields_are_not_dropped(self) -> None:
        for section in (None, "record", "audit_entry", "integration_event"):
            with self.subTest(section=section):
                document = copy.deepcopy(self.document)
                target = document if section is None else document[section]
                target["unknown"] = "discarded"
                with self.assertRaises(RepositoryIntegrityError):
                    _result_from_json(json.dumps(document), replayed=True)
        text = json.dumps(self.document)
        duplicate = text.replace(
            '"request_sha256":', '"request_sha256":"sha256:' + "0" * 64 + '","request_sha256":', 1
        )
        with self.assertRaises(RepositoryIntegrityError):
            _result_from_json(duplicate, replayed=True)
        event_json = json.dumps(self.document["integration_event"])
        duplicate_event = event_json.replace(
            '"event_id":',
            '"event_id":'
            + json.dumps(self.document["integration_event"]["event_id"])
            + ',"event_id":',
            1,
        )
        nested_duplicate = json.dumps(self.document).replace(event_json, duplicate_event)
        with self.assertRaises(RepositoryIntegrityError):
            _result_from_json(nested_duplicate, replayed=True)
        for value in (True, 1.0):
            with self.subTest(version=value):
                with self.assertRaises(RepositoryIntegrityError):
                    _result_from_json(
                        json.dumps(self.changed("integration_event", "resource_version", value)),
                        replayed=True,
                    )

    def test_missing_persisted_fields_and_noninteger_versions_fail_before_return(self) -> None:
        for section, field in (
            (None, "request_sha256"),
            ("record", "created_at"),
            ("audit_entry", "principal_id"),
            ("integration_event", "event_id"),
        ):
            with self.subTest(section=section, field=field):
                document = copy.deepcopy(self.document)
                target = document if section is None else document[section]
                del target[field]
                with self.assertRaises(RepositoryIntegrityError):
                    _result_from_json(json.dumps(document), replayed=True)
        for section, field in (("record", "version"), ("integration_event", "resource_version")):
            for value in (False, True, 1.0, "1", None):
                with self.subTest(section=section, value=value):
                    with self.assertRaises(RepositoryIntegrityError):
                        _result_from_json(
                            json.dumps(self.changed(section, field, value)), replayed=True
                        )

    def test_service_replay_and_commit_bind_original_request_principal_and_prior_token(
        self,
    ) -> None:
        for changes in (
            {"principal_id": "principal-other"},
            {"prior_concurrency_token": "ct:" + "0" * 64},
        ):
            with self.subTest(changes=changes):
                result = replace(
                    self.original, audit_entry=replace(self.original.audit_entry, **changes)
                )
                with self.assertRaises(LocalApiServiceError):
                    _validate_commit_result(result, self.typed_request)

    def test_coherently_readdressed_same_id_payload_does_not_replay_another_request(self) -> None:
        old = self.original.record
        payload = {**dict(old.payload), "name": "Substituted resource payload"}
        payload_sha = canonical_sha256(payload)
        token = _concurrency_token(
            old.resource_kind,
            old.resource_id,
            old.tenant_id,
            old.context_id,
            old.version,
            payload_sha,
            old.audit_refs,
        )
        record = replace(old, payload=payload, payload_sha256=payload_sha, concurrency_token=token)
        audit = replace(self.original.audit_entry, resulting_concurrency_token=token)
        event = replace(
            self.original.integration_event, resource_sha256=canonical_sha256(record.to_dict())
        )
        event = replace(
            event,
            event_id="event:"
            + canonical_sha256(
                {
                    "audit_ref": event.audit_ref,
                    "event_type": event.event_type,
                    "resource_sha256": event.resource_sha256,
                }
            )[7:],
        )
        document = _result_document(
            replace(self.original, record=record, audit_entry=audit, integration_event=event)
        )
        status, response, _ = self.read_replay(document)
        self.assertNotEqual(status, 200)
        self.assertNotIn("data", response)

    def test_coherent_resource_principal_and_time_substitution_fail_public_replay(self) -> None:
        for changes in (
            {"resource_id": "asset-other"},
            {"tenant_id": "tenant-other"},
            {"context_id": "context-other"},
            {"created_at": "2026-09-20T12:00:01Z", "updated_at": "2026-09-20T12:00:01Z"},
        ):
            with self.subTest(changes=changes):
                old = self.original.record
                values = {**old.to_dict(), **changes}
                values["concurrency_token"] = _concurrency_token(
                    old.resource_kind,
                    values["resource_id"],
                    values["tenant_id"],
                    values["context_id"],
                    old.version,
                    old.payload_sha256,
                    old.audit_refs,
                )
                record = replace(old, **changes, concurrency_token=values["concurrency_token"])
                audit = replace(
                    self.original.audit_entry,
                    resource_id=record.resource_id,
                    tenant_id=record.tenant_id,
                    context_id=record.context_id,
                    recorded_at=record.updated_at,
                    resulting_concurrency_token=record.concurrency_token,
                )
                event = self.readdress_event(
                    self.original.integration_event,
                    record,
                    resource_id=record.resource_id,
                    tenant_id=record.tenant_id,
                    context_id=record.context_id,
                    occurred_at=record.updated_at,
                )
                document = _result_document(
                    replace(
                        self.original, record=record, audit_entry=audit, integration_event=event
                    )
                )
                # A retained document alone cannot recover the absent request body.
                _result_from_json(json.dumps(document), replayed=True)
                status, response, _ = self.read_replay(document)
                self.assertNotEqual(status, 200)
                self.assertNotIn("data", response)
        document = self.changed("audit_entry", "principal_id", "principal-other")
        _result_from_json(json.dumps(document), replayed=True)
        self.assertNotEqual(self.read_replay(document)[0], 200)

    def test_new_commit_response_must_preserve_exact_constructed_evidence(self) -> None:
        request = fixtures.create_request("asset-fresh-integrity")
        before = self.fixture.repository.verify_integrity()
        for section, changes in (
            ("audit_entry", {"admission_audit_ref": "auditref:substituted"}),
            ("audit_entry", {"principal_id": "principal-other"}),
            ("integration_event", {"resource_id": "asset-other"}),
            ("integration_event", {"resource_version": True}),
            ("integration_event", {"resource_version": 1.0}),
        ):
            with self.subTest(section=section, changes=changes):

                def corrupted_result(command):
                    result = CommitResult(
                        request_sha256=command.request_sha256,
                        idempotency_sha256=command.idempotency_sha256,
                        record=command.record,
                        audit_entry=command.audit_entry,
                        integration_event=command.integration_event,
                        replayed=False,
                    )
                    return replace(
                        result, **{section: replace(getattr(result, section), **changes)}
                    )

                with mock.patch.object(
                    self.fixture.repository, "commit", side_effect=corrupted_result
                ) as commit:
                    status, response, _ = self.fixture.call(request)
                self.assertNotEqual(status, 200)
                self.assertNotIn("data", response)
                self.assertEqual(commit.call_count, 1)
                self.assertEqual(self.fixture.repository.verify_integrity(), before)

    def test_actual_update_command_and_return_preserve_prior_creation_time(self) -> None:
        captured = []
        original_commit = self.fixture.repository.commit

        def capture(command):
            captured.append(command)
            return original_commit(command)

        with mock.patch.object(self.fixture.repository, "commit", side_effect=capture):
            self.assertEqual(self.fixture.call(self.update_request())[0], 200)
        command = captured[0]
        record = replace(command.record, created_at="2026-09-20T11:59:59Z")
        event = self.readdress_event(command.integration_event, record)
        changed = replace(command, record=record, integration_event=event)
        with self.assertRaises(RepositoryIntegrityError):
            _validate_commit_command(changed)
        next_request = {
            **self.update_request(),
            "request_id": "request-next-update-integrity",
            "expected_concurrency_token": command.record.concurrency_token,
            "idempotency_key": "idem:update-integrity-00000002",
            "requested_at": "2026-09-20T12:00:02Z",
        }

        def changed_creation(command):
            record = replace(command.record, created_at="2026-09-20T11:59:59Z")
            return CommitResult(
                request_sha256=command.request_sha256,
                idempotency_sha256=command.idempotency_sha256,
                record=record,
                audit_entry=command.audit_entry,
                integration_event=self.readdress_event(command.integration_event, record),
                replayed=False,
            )

        before = self.fixture.repository.verify_integrity()
        with mock.patch.object(self.fixture.repository, "commit", side_effect=changed_creation):
            self.assertNotEqual(self.fixture.call(next_request)[0], 200)
        self.assertEqual(self.fixture.repository.verify_integrity(), before)

    def test_persisted_event_operation_reproduces_create_update_semantics(self) -> None:
        event = self.readdress_event(
            self.original.integration_event,
            self.original.record,
            event_type="asset.update_asset",
        )
        document = _result_document(replace(self.original, integration_event=event))
        with self.assertRaises(RepositoryIntegrityError):
            _result_from_json(json.dumps(document), replayed=True)
        update = self.update_request()
        self.assertEqual(self.fixture.call(update)[0], 200)
        result = self.fixture.repository.lookup_idempotency(
            "tenant-a", "context-red", _service_request(update).idempotency_sha256
        )
        event = self.readdress_event(
            result.integration_event, result.record, event_type="asset.create_asset"
        )
        document = _result_document(replace(result, integration_event=event))
        with self.assertRaises(RepositoryIntegrityError):
            _result_from_json(json.dumps(document), replayed=True)

    def test_retained_update_requires_last_audit_not_merely_membership(self) -> None:
        update = self.update_request()
        self.assertEqual(self.fixture.call(update)[0], 200)
        result = self.fixture.repository.lookup_idempotency(
            "tenant-a", "context-red", _service_request(update).idempotency_sha256
        )
        refs = tuple(reversed(result.record.audit_refs))
        old = result.record
        token = _concurrency_token(
            old.resource_kind,
            old.resource_id,
            old.tenant_id,
            old.context_id,
            old.version,
            old.payload_sha256,
            refs,
        )
        record = replace(old, audit_refs=refs, concurrency_token=token)
        audit = replace(result.audit_entry, resulting_concurrency_token=token)
        event = self.readdress_event(result.integration_event, record)
        document = _result_document(
            replace(result, record=record, audit_entry=audit, integration_event=event)
        )
        self.assertIn(audit.audit_ref, record.audit_refs)
        with self.assertRaises(RepositoryIntegrityError):
            _result_from_json(json.dumps(document), replayed=True)
        version = old.version + 1
        token = _concurrency_token(
            old.resource_kind,
            old.resource_id,
            old.tenant_id,
            old.context_id,
            version,
            old.payload_sha256,
            old.audit_refs,
        )
        record = replace(old, version=version, concurrency_token=token)
        audit = replace(result.audit_entry, resulting_concurrency_token=token)
        event = self.readdress_event(result.integration_event, record, resource_version=version)
        document = _result_document(
            replace(result, record=record, audit_entry=audit, integration_event=event)
        )
        with self.assertRaises(RepositoryIntegrityError):
            _result_from_json(json.dumps(document), replayed=True)

    def test_coherent_replay_prior_token_is_bound_to_the_original_update_request(self) -> None:
        request = self.update_request()
        self.assertEqual(self.fixture.call(request)[0], 200)
        result = self.fixture.repository.lookup_idempotency(
            "tenant-a", "context-red", _service_request(request).idempotency_sha256
        )
        prior_token = "ct:" + "0" * 64
        audit_ref = (
            "auditref:"
            + canonical_sha256(
                {
                    "admission_ref": result.audit_entry.admission_ref,
                    "authorization_ref": result.audit_entry.authorization_ref,
                    "prior_token": prior_token,
                    "request_sha256": result.request_sha256,
                }
            )[7:]
        )
        old = result.record
        refs = (*old.audit_refs[:-1], audit_ref)
        token = _concurrency_token(
            old.resource_kind,
            old.resource_id,
            old.tenant_id,
            old.context_id,
            old.version,
            old.payload_sha256,
            refs,
        )
        record = replace(old, audit_refs=refs, concurrency_token=token)
        audit = replace(
            result.audit_entry,
            audit_ref=audit_ref,
            prior_concurrency_token=prior_token,
            resulting_concurrency_token=token,
        )
        event = self.readdress_event(result.integration_event, record, audit_ref=audit_ref)
        document = _result_document(
            replace(result, record=record, audit_entry=audit, integration_event=event)
        )
        _result_from_json(json.dumps(document), replayed=True)
        status, response, _ = self.read_replay(document, request)
        self.assertNotEqual(status, 200)
        self.assertNotIn("data", response)

    def test_exact_replay_retains_historical_refs_after_current_decisions_change(self) -> None:
        class CurrentAuthorizer(fixtures.BoundAuthorizer):
            def authorize(self, check):
                return replace(super().authorize(check), decision_ref="authzref:current-different")

        class CurrentAdmitter(fixtures.BoundAdmitter):
            def admit(self, check):
                return replace(super().admit(check), admission_ref="admitref:current-different")

        self.fixture.app = LocalApiAsgiApp(
            self.fixture.repository, CurrentAuthorizer(), CurrentAdmitter()
        )
        status, response, _ = self.fixture.call(self.request)
        self.assertEqual(status, 200)
        self.assertEqual(response["data"]["status"], "replayed")
        self.assertEqual(response["data"]["resource"], self.created["data"]["resource"])
        self.assertEqual(
            response["data"]["integration_event"], self.created["data"]["integration_event"]
        )
        stored = self.fixture.repository.lookup_idempotency(
            "tenant-a", "context-red", self.typed_request.idempotency_sha256
        )
        self.assertEqual(_result_document(stored), self.document)
        self.assertEqual(self.fixture.repository.verify_integrity()["audit_entries"], 1)
        # An atomic repository can discover an exact replay after the earlier lookup.
        # Its original refs differ from this newly constructed command, intentionally.
        with (
            mock.patch.object(self.fixture.repository, "get", return_value=None),
            mock.patch.object(self.fixture.repository, "lookup_idempotency", return_value=None),
        ):
            status, raced, _ = self.fixture.call(self.request)
        self.assertEqual(status, 200)
        self.assertEqual(raced["data"]["status"], "replayed")
        self.assertEqual(raced["data"]["resource"], self.created["data"]["resource"])
        self.assertEqual(
            raced["data"]["integration_event"], self.created["data"]["integration_event"]
        )
        self.assertEqual(self.fixture.repository.verify_integrity()["audit_entries"], 1)

    def test_genuine_restart_update_and_historical_replay_preserve_snapshots(self) -> None:
        reopened = SQLiteServiceRepository(self.fixture.database)
        self.fixture.repository = reopened
        self.fixture.app = LocalApiAsgiApp(
            reopened, fixtures.BoundAuthorizer(), fixtures.BoundAdmitter()
        )
        update = self.update_request()
        status, updated, _ = self.fixture.call(update)
        self.assertEqual(status, 200)
        self.assertEqual(updated["data"]["resource"]["version"], 2)
        status, replayed, _ = self.fixture.call(self.request)
        self.assertEqual(status, 200)
        self.assertEqual(replayed["data"]["status"], "replayed")
        self.assertEqual(replayed["data"]["resource"], self.created["data"]["resource"])
        self.assertEqual(reopened.verify_integrity()["idempotency_results"], 2)


if __name__ == "__main__":
    unittest.main()

"""Phase 133 executor invocation preparation and resolution coverage."""

from __future__ import annotations

import ast
import json
import unittest
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from sunderkey.collaboration_executor import (
    build_collaboration_executor_acknowledgement,
)
from sunderkey.collaboration_executor_invocation_attempt import (
    CollaborationExecutorInvocationPreparation,
    CollaborationExecutorInvocationResolution,
    build_collaboration_executor_invocation_preparation,
    build_collaboration_executor_invocation_resolution,
)
from sunderkey.errors import CollaborationPlanError

from . import test_collaboration_executor_delivery_claim_store_phase132 as phase132

ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = ROOT / "registry/schemas"
ADAPTER_BUILD = "sha256:" + "91" * 32
DEPLOYMENT_BINDING = "sha256:" + "92" * 32
IDEMPOTENCY_KEY = "sha256:" + "93" * 32
EVIDENCE = "sha256:" + "94" * 32


class CollaborationExecutorInvocationAttemptPhase133Tests(unittest.TestCase):
    def setUp(self) -> None:
        fixture = phase132.CollaborationExecutorDeliveryClaimStorePhase132Tests(
            methodName="runTest"
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        self.claim_receipt = fixture._claim()
        self.operation_input = fixture.fixture.fixture.operation_input
        self.dispatch = fixture.fixture.fixture.dispatch

    def _prepare(
        self,
        *,
        operation_input: bytes | None = None,
        idempotency_status: str = "absent",
        idempotency_key_sha256: str | None = None,
    ) -> CollaborationExecutorInvocationPreparation:
        return build_collaboration_executor_invocation_preparation(
            self.claim_receipt,
            self.operation_input if operation_input is None else operation_input,
            adapter_id="adapter.test",
            adapter_version="1.0.0",
            adapter_build_sha256=ADAPTER_BUILD,
            deployment_binding_sha256=DEPLOYMENT_BINDING,
            idempotency_status=idempotency_status,
            idempotency_key_sha256=idempotency_key_sha256,
            prepared_at="2026-07-30T10:08:31Z",
        )

    def _acknowledgement(self, *, adapter_id: str = "adapter.test"):
        operation = self.dispatch.to_dict()["operation"]
        state = {
            "start": "ready",
            "action": "active",
            "evidence": "unchanged",
            "heartbeat": "active",
            "pause": "paused",
            "resume": "active",
            "stop": "stopped",
            "destroy": "destroyed",
        }[operation]
        return build_collaboration_executor_acknowledgement(
            self.dispatch,
            adapter_id=adapter_id,
            adapter_version="1.0.0",
            adapter_build_sha256=ADAPTER_BUILD,
            runtime_instance_id="worker-runtime-1",
            outcome="accepted",
            provider_worker_state=state,
            provider_evidence_sha256=EVIDENCE,
            acknowledged_at="2026-07-30T10:08:34Z",
        )

    def test_preparation_revalidates_exact_bytes_and_remains_inert(self) -> None:
        preparation = self._prepare()
        document = preparation.to_dict()
        self.assertEqual(document["attempt_status"], "prepared_before_invocation")
        self.assertEqual(document["external_effect_status"], "not_started")
        self.assertEqual(document["runtime_effect"], "none")
        with self.assertRaisesRegex(CollaborationPlanError, "input hash"):
            self._prepare(operation_input=b"changed")

    def test_idempotency_claim_is_strict(self) -> None:
        with self.assertRaisesRegex(CollaborationPlanError, "Absent idempotency"):
            self._prepare(idempotency_key_sha256=IDEMPOTENCY_KEY)
        verified = self._prepare(
            idempotency_status="verified",
            idempotency_key_sha256=IDEMPOTENCY_KEY,
        )
        self.assertEqual(
            verified.to_dict()["idempotency"]["status"],
            "verified",
        )

    def test_failed_before_invocation_allows_safe_retry(self) -> None:
        resolution = build_collaboration_executor_invocation_resolution(
            self._prepare(),
            outcome="failed_before_invocation",
            failure_code="adapter-not-started",
            resolved_at="2026-07-30T10:08:32Z",
        )
        document = resolution.to_dict()
        self.assertEqual(document["external_effect_status"], "not_started")
        self.assertEqual(
            document["retry_disposition"],
            "retry_allowed_no_external_effect",
        )

    def test_uncertain_outcome_forbids_blind_retry(self) -> None:
        unverified = build_collaboration_executor_invocation_resolution(
            self._prepare(),
            outcome="outcome_uncertain",
            failure_code="response-lost",
            resolved_at="2026-07-30T10:08:36Z",
        )
        self.assertEqual(
            unverified.to_dict()["retry_disposition"],
            "retry_forbidden_uncertain_effect",
        )
        changed = unverified.to_dict()
        changed["retry_disposition"] = "retry_allowed_verified_idempotency"
        with self.assertRaisesRegex(CollaborationPlanError, "boundary"):
            CollaborationExecutorInvocationResolution.from_dict(changed)
        verified = build_collaboration_executor_invocation_resolution(
            self._prepare(
                idempotency_status="verified",
                idempotency_key_sha256=IDEMPOTENCY_KEY,
            ),
            outcome="outcome_uncertain",
            failure_code="response-lost",
            resolved_at="2026-07-30T10:08:36Z",
        )
        self.assertEqual(
            verified.to_dict()["retry_disposition"],
            "retry_allowed_verified_idempotency",
        )

    def test_provider_report_is_exactly_bound_but_not_yet_authenticated(self) -> None:
        resolution = build_collaboration_executor_invocation_resolution(
            self._prepare(),
            outcome="provider_report_received",
            provider_acknowledgement=self._acknowledgement(),
            resolved_at="2026-07-30T10:08:35Z",
        )
        document = resolution.to_dict()
        self.assertEqual(
            document["external_effect_status"],
            "provider_report_pending_authentication",
        )
        self.assertEqual(document["runtime_effect"], "none")
        with self.assertRaisesRegex(CollaborationPlanError, "report is stale"):
            build_collaboration_executor_invocation_resolution(
                self._prepare(),
                outcome="provider_report_received",
                provider_acknowledgement=self._acknowledgement(
                    adapter_id="adapter.changed"
                ),
                resolved_at="2026-07-30T10:08:35Z",
            )

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_contracts_match_strict_schemas(self) -> None:
        preparation_schema = json.loads(
            (
                SCHEMAS
                / "collaboration-executor-invocation-preparation-v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        resolution_schema = json.loads(
            (
                SCHEMAS
                / "collaboration-executor-invocation-resolution-v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        for schema, document in (
            (preparation_schema, self._prepare().to_dict()),
            (
                resolution_schema,
                build_collaboration_executor_invocation_resolution(
                    self._prepare(),
                    outcome="outcome_uncertain",
                    failure_code="response-lost",
                    resolved_at="2026-07-30T10:08:36Z",
                ).to_dict(),
            ),
        ):
            Draft202012Validator.check_schema(schema)
            Draft202012Validator(schema).validate(document)

    def test_contract_has_no_network_process_or_adapter_invocation(self) -> None:
        source_path = ROOT / "src/sunderkey/collaboration_executor_invocation_attempt.py"
        source = source_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        imports = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        self.assertFalse(
            imports
            & {
                "asyncio",
                "httpx",
                "requests",
                "socket",
                "subprocess",
                "urllib",
            }
        )
        self.assertNotIn("CollaborationExecutorAdapter", source)


if __name__ == "__main__":
    unittest.main()

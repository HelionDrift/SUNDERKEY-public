"""Phase 125 provider-neutral collaboration executor contract coverage."""

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
    ACCEPTED_STATES,
    OPERATIONS,
    CollaborationExecutorAcknowledgement,
    CollaborationExecutorDispatchEnvelope,
    build_collaboration_executor_acknowledgement,
    build_collaboration_executor_dispatch,
    collaboration_executor_operation_input_sha256,
    validate_collaboration_executor_acknowledgement,
    validate_collaboration_executor_operation_input,
)
from sunderkey.errors import CollaborationPlanError

from . import test_collaboration_execution_session_status_phase124 as phase124

ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = ROOT / "registry/schemas"
TOOL_POLICY_SHA256 = "sha256:" + "71" * 32
ADAPTER_BUILD_SHA256 = "sha256:" + "72" * 32
EVIDENCE_SHA256 = "sha256:" + "73" * 32


class CollaborationExecutorPhase125Tests(unittest.TestCase):
    def setUp(self) -> None:
        fixture = phase124.CollaborationExecutionSessionStatusPhase124Tests(
            methodName="runTest"
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        self.fixture.fixture._activate()
        self.status = self.fixture._get()
        self.authority = self.fixture.fixture.authority
        self.plan = self.fixture.fixture.root.plan
        self.operation_input = b'{"operation":"contract-only"}'

    def _dispatch(
        self,
        operation: str = "start",
        *,
        sequence: int = 1,
    ) -> CollaborationExecutorDispatchEnvelope:
        return build_collaboration_executor_dispatch(
            status=self.status,
            authority=self.authority,
            collaboration_plan=self.plan,
            operation=operation,
            operation_sequence=sequence,
            tool_policy_sha256=TOOL_POLICY_SHA256,
            operation_input_sha256=(
                collaboration_executor_operation_input_sha256(
                    self.operation_input
                )
            ),
            issued_at="2026-07-30T10:08:10Z",
            expires_at="2026-07-30T10:09:00Z",
        )

    def _acknowledgement(
        self,
        dispatch: CollaborationExecutorDispatchEnvelope,
        *,
        state: str = "ready",
        outcome: str = "accepted",
        acknowledged_at: str = "2026-07-30T10:08:20Z",
    ) -> CollaborationExecutorAcknowledgement:
        return build_collaboration_executor_acknowledgement(
            dispatch,
            adapter_id="adapter.contract-test",
            adapter_version="1.0.0",
            adapter_build_sha256=ADAPTER_BUILD_SHA256,
            runtime_instance_id="worker.instance-001",
            outcome=outcome,
            provider_worker_state=state,
            provider_evidence_sha256=EVIDENCE_SHA256,
            acknowledged_at=acknowledged_at,
        )

    def test_dispatch_binds_exact_authority_plan_worker_fence_and_input(self) -> None:
        dispatch = self._dispatch()
        document = dispatch.to_dict()
        authority = self.authority.to_dict()
        session = authority["session"]
        self.assertEqual(document["operation"], "start")
        self.assertEqual(
            document["session_authority"]["session_authority_id"],
            self.authority.session_authority_id,
        )
        self.assertEqual(document["mission"]["mission_sha256"], self.plan.mission_sha256)
        self.assertEqual(
            document["worker"]["worker_principal_id"],
            session["worker_principal_id"],
        )
        self.assertEqual(
            document["worker"]["fence_generation"],
            session["fence_generation"],
        )
        self.assertEqual(document["dispatch_status"], "prepared_provider_dispatch")
        self.assertEqual(document["runtime_effect"], "none")
        self.assertEqual(
            CollaborationExecutorDispatchEnvelope.from_dict(document),
            dispatch,
        )

    def test_all_required_adapter_operations_have_strict_accepted_states(self) -> None:
        for sequence, operation in enumerate(OPERATIONS, start=1):
            with self.subTest(operation=operation):
                dispatch = self._dispatch(operation, sequence=sequence)
                state = sorted(ACCEPTED_STATES[operation])[0]
                acknowledgement = self._acknowledgement(dispatch, state=state)
                self.assertEqual(
                    validate_collaboration_executor_acknowledgement(
                        dispatch,
                        acknowledgement,
                    ),
                    acknowledgement,
                )

    def test_acknowledgement_is_explicitly_unverified_provider_report(self) -> None:
        dispatch = self._dispatch()
        acknowledgement = self._acknowledgement(dispatch)
        document = acknowledgement.to_dict()
        self.assertEqual(
            document["authentication_status"],
            "provider_assertion_unverified",
        )
        self.assertEqual(document["external_effect_status"], "provider_report_only")
        self.assertEqual(document["runtime_effect"], "none")
        self.assertEqual(
            CollaborationExecutorAcknowledgement.from_dict(document),
            acknowledgement,
        )

    def test_out_of_band_operation_input_must_match_dispatch_hash(self) -> None:
        dispatch = self._dispatch()
        validate_collaboration_executor_operation_input(
            dispatch,
            self.operation_input,
        )
        with self.assertRaisesRegex(CollaborationPlanError, "input hash"):
            validate_collaboration_executor_operation_input(
                dispatch,
                b'{"operation":"changed"}',
            )

    def test_revocation_closes_ordinary_dispatch_but_preserves_stop(self) -> None:
        self.fixture.fixture._revoke()
        revoked = self.fixture._get()
        with self.assertRaisesRegex(CollaborationPlanError, "not available"):
            build_collaboration_executor_dispatch(
                status=revoked,
                authority=self.authority,
                collaboration_plan=self.plan,
                operation="action",
                operation_sequence=2,
                tool_policy_sha256=TOOL_POLICY_SHA256,
                operation_input_sha256=(
                    collaboration_executor_operation_input_sha256(b"stop")
                ),
                issued_at="2026-07-30T10:09:10Z",
                expires_at="2026-07-30T10:10:00Z",
            )
        stop = build_collaboration_executor_dispatch(
            status=revoked,
            authority=self.authority,
            collaboration_plan=self.plan,
            operation="stop",
            operation_sequence=2,
            tool_policy_sha256=TOOL_POLICY_SHA256,
            operation_input_sha256=(
                collaboration_executor_operation_input_sha256(b"stop")
            ),
            issued_at="2026-07-30T10:09:10Z",
            expires_at="2026-07-30T10:10:00Z",
        )
        self.assertEqual(stop.to_dict()["operation"], "stop")

    def test_acknowledgement_rejects_wrong_state_late_or_stale_fence(self) -> None:
        dispatch = self._dispatch()
        with self.assertRaisesRegex(CollaborationPlanError, "accepted worker state"):
            self._acknowledgement(dispatch, state="destroyed")
        late = self._acknowledgement(
            dispatch,
            acknowledged_at="2026-07-30T10:09:01Z",
        )
        with self.assertRaisesRegex(CollaborationPlanError, "late"):
            validate_collaboration_executor_acknowledgement(dispatch, late)
        changed = self._acknowledgement(dispatch).to_dict()
        changed["worker"]["fence_generation"] += 1
        with self.assertRaisesRegex(CollaborationPlanError, "hash"):
            CollaborationExecutorAcknowledgement.from_dict(changed)

    def test_contracts_validate_against_published_schemas(self) -> None:
        if Draft202012Validator is None:
            self.skipTest("jsonschema is not installed")
        dispatch = self._dispatch()
        acknowledgement = self._acknowledgement(dispatch)
        for schema_name, document in (
            ("collaboration-executor-dispatch-v1.schema.json", dispatch.to_dict()),
            (
                "collaboration-executor-acknowledgement-v1.schema.json",
                acknowledgement.to_dict(),
            ),
        ):
            with self.subTest(schema=schema_name):
                schema = json.loads((SCHEMAS / schema_name).read_text(encoding="utf-8"))
                Draft202012Validator(schema).validate(document)

    def test_contract_module_has_no_runtime_or_network_adapter_implementation(self) -> None:
        source_path = ROOT / "src/sunderkey/collaboration_executor.py"
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        imported_roots = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imported_roots.update(
            node.module.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
            and node.module is not None
        )
        self.assertTrue(
            imported_roots.isdisjoint(
                {"http", "requests", "socket", "subprocess", "urllib"}
            )
        )


if __name__ == "__main__":
    unittest.main()

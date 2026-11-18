"""Phase 115 terminal execution transfer custody preflight coverage."""

from __future__ import annotations

import ast
import copy
import json
import tempfile
import unittest
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from sunderkey.collaboration_execution_terminal_custody import (
    CollaborationExecutionTerminalCustodyPlan,
    build_collaboration_execution_terminal_custody_plan,
    load_collaboration_execution_terminal_custody_plan,
)
from sunderkey.collaboration_execution_transfer_completion import (
    build_collaboration_execution_transfer_completion,
)
from sunderkey.errors import CollaborationPlanError

from . import test_collaboration_execution_timeout_authentication_phase113 as phase113
from . import test_collaboration_execution_transfer_completion_phase114 as phase114

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "registry/schemas/collaboration-execution-terminal-custody-plan-v1.schema.json"


class CollaborationExecutionTerminalCustodyPhase115Tests(unittest.TestCase):
    def setUp(self) -> None:
        fixture = phase114.CollaborationExecutionTransferCompletionPhase114Tests(
            methodName="runTest"
        )
        fixture.setUp()
        self.fixture = fixture
        self.completion = fixture._completion()

    def _completed_plan(self, **overrides):
        arguments = {
            "authenticated_request": self.fixture.fixture.authenticated_request,
            "acknowledgements": self.fixture.acknowledgements,
            "completion": self.completion,
        }
        arguments.update(overrides)
        return build_collaboration_execution_terminal_custody_plan(**arguments)

    def test_completed_plan_orders_every_assertion_for_atomic_consumption(self) -> None:
        plan = self._completed_plan()
        document = plan.to_dict()
        self.assertTrue(plan.custody_plan_id.startswith("ECT-"))
        self.assertEqual(document["terminal_kind"], "completed")
        self.assertEqual(
            [item["role"] for item in document["participant_authentications"]],
            ["control_plane_requester", "source_worker", "target_worker"],
        )
        self.assertEqual(
            document["assertion_consumption_order"],
            [item["authentication_id"] for item in document["participant_authentications"]],
        )
        self.assertEqual(document["custody_status"], "ready_for_atomic_commit")
        self.assertFalse(document["recovery_required"])
        self.assertEqual(document["runtime_effect"], "none")

    def test_timeout_plan_includes_independent_control_last(self) -> None:
        timeout_fixture = phase113.CollaborationExecutionTimeoutAuthenticationPhase113Tests(
            methodName="runTest"
        )
        timeout_fixture.setUp()
        authenticated_timeout = timeout_fixture._authenticate()
        request = timeout_fixture.fixture.fixture.authenticated_request
        plan = build_collaboration_execution_terminal_custody_plan(
            authenticated_request=request,
            acknowledgements=timeout_fixture.observed,
            authenticated_timeout=authenticated_timeout,
        )
        document = plan.to_dict()
        self.assertEqual(document["terminal_kind"], "failed_closed_timeout")
        self.assertEqual(
            [item["role"] for item in document["participant_authentications"]],
            ["control_plane_requester", "source_worker", "independent_control"],
        )
        self.assertTrue(document["recovery_required"])
        self.assertEqual(
            document["outcome_authentication"]["authentication_id"],
            authenticated_timeout.authentication_id,
        )

    def test_terminal_branches_are_mutually_exclusive(self) -> None:
        timeout_fixture = phase113.CollaborationExecutionTimeoutAuthenticationPhase113Tests(
            methodName="runTest"
        )
        timeout_fixture.setUp()
        with self.assertRaisesRegex(CollaborationPlanError, "Exactly one"):
            build_collaboration_execution_terminal_custody_plan(
                authenticated_request=self.fixture.fixture.authenticated_request,
                acknowledgements=self.fixture.acknowledgements,
            )
        with self.assertRaisesRegex(CollaborationPlanError, "Exactly one"):
            self._completed_plan(authenticated_timeout=timeout_fixture._authenticate())

    def test_stale_completion_and_participant_tampering_fail_closed(self) -> None:
        changed_completion = build_collaboration_execution_transfer_completion(
            authenticated_request=self.fixture.fixture.authenticated_request,
            acknowledgements=list(reversed(self.fixture.acknowledgements)),
        )
        self.assertEqual(changed_completion.completion_id, self.completion.completion_id)
        plan = self._completed_plan()
        changed = copy.deepcopy(plan.to_dict())
        changed["participant_authentications"][0]["role"] = "source_worker"
        with self.assertRaisesRegex(CollaborationPlanError, "operation"):
            CollaborationExecutionTerminalCustodyPlan.from_dict(changed)
        changed = copy.deepcopy(plan.to_dict())
        changed["assertion_consumption_order"].reverse()
        with self.assertRaisesRegex(CollaborationPlanError, "assertion order"):
            CollaborationExecutionTerminalCustodyPlan.from_dict(changed)

    def test_hash_loader_and_schema_are_strict(self) -> None:
        plan = self._completed_plan()
        changed = copy.deepcopy(plan.to_dict())
        changed["custody_status"] = "committed"
        with self.assertRaisesRegex(CollaborationPlanError, "custody status"):
            CollaborationExecutionTerminalCustodyPlan.from_dict(changed)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "custody-plan.json"
            path.write_text(json.dumps(plan.to_dict()), encoding="utf-8")
            self.assertEqual(
                load_collaboration_execution_terminal_custody_plan(path).custody_plan_id,
                plan.custody_plan_id,
            )
            path.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
            with self.assertRaisesRegex(CollaborationPlanError, "Could not load"):
                load_collaboration_execution_terminal_custody_plan(path)
        if Draft202012Validator is not None:
            Draft202012Validator(json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))).validate(
                plan.to_dict()
            )

    def test_module_has_no_runtime_storage_or_network_imports(self) -> None:
        tree = ast.parse(
            (ROOT / "src/sunderkey/collaboration_execution_terminal_custody.py").read_text(
                encoding="utf-8"
            )
        )
        imported = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imported.update(
            (node.module or "").split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.level == 0
        )
        self.assertFalse(
            imported & {"asyncio", "http", "requests", "socket", "sqlite3", "subprocess", "urllib"}
        )


if __name__ == "__main__":
    unittest.main()

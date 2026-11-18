"""Phase 114 successful execution transfer completion coverage."""

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

from sunderkey.collaboration_execution_transfer_completion import (
    CollaborationExecutionTransferCompletion,
    build_collaboration_execution_transfer_completion,
    load_collaboration_execution_transfer_completion,
    validate_collaboration_execution_transfer_completion,
)
from sunderkey.errors import CollaborationPlanError

from . import test_collaboration_execution_transfer_authentication_phase111 as phase111

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "registry/schemas/collaboration-execution-transfer-completion-v1.schema.json"


class CollaborationExecutionTransferCompletionPhase114Tests(unittest.TestCase):
    def setUp(self) -> None:
        fixture = phase111.CollaborationExecutionTransferAuthenticationPhase111Tests(
            methodName="runTest"
        )
        fixture.setUpClass()
        fixture.setUp()
        self.fixture = fixture
        self.source_authentication, self.source_session = fixture._authenticate_acknowledgement(
            "source_released"
        )
        self.target_authentication, self.target_session = fixture._authenticate_acknowledgement(
            "target_accepted"
        )
        self.acknowledgements = [
            (self.source_authentication, self.source_session),
            (self.target_authentication, self.target_session),
        ]

    def _completion(self, acknowledgements=None):
        return build_collaboration_execution_transfer_completion(
            authenticated_request=self.fixture.authenticated_request,
            acknowledgements=(
                self.acknowledgements if acknowledgements is None else acknowledgements
            ),
        )

    def test_complete_authenticated_set_is_eligible_only_after_atomic_commit(self) -> None:
        completion = self._completion()
        document = completion.to_dict()
        self.assertTrue(completion.completion_id.startswith("ETC-"))
        self.assertEqual(document["completion_outcome"], "acknowledged_complete")
        self.assertEqual(document["source_session_disposition"], "revoked_unavailable")
        self.assertEqual(
            document["target_session_disposition"],
            "eligible_after_atomic_commit",
        )
        self.assertTrue(document["durable_commit_required"])
        self.assertEqual(document["activation_status"], "pending_atomic_durable_commit")
        self.assertEqual(document["runtime_effect"], "none")
        validated = validate_collaboration_execution_transfer_completion(
            completion,
            authenticated_request=self.fixture.authenticated_request,
            acknowledgements=self.acknowledgements,
        )
        self.assertEqual(validated.completion_id, completion.completion_id)

    def test_acknowledgements_are_canonicalized_in_required_order(self) -> None:
        completion = self._completion(list(reversed(self.acknowledgements)))
        kinds = [
            item["acknowledgement_kind"]
            for item in completion.to_dict()["completed_acknowledgements"]
        ]
        self.assertEqual(kinds, ["source_released", "target_accepted"])
        self.assertEqual(completion.completion_id, self._completion().completion_id)

    def test_incomplete_and_duplicate_sets_fail_closed(self) -> None:
        with self.assertRaisesRegex(CollaborationPlanError, "incomplete"):
            self._completion([(self.source_authentication, self.source_session)])
        with self.assertRaisesRegex(CollaborationPlanError, "incomplete"):
            self._completion(
                [
                    (self.source_authentication, self.source_session),
                    (self.source_authentication, self.source_session),
                ]
            )

    def test_hash_and_completion_invariants_fail_closed(self) -> None:
        completion = self._completion()
        changed = copy.deepcopy(completion.to_dict())
        changed["activation_status"] = "active"
        with self.assertRaisesRegex(CollaborationPlanError, "activation status"):
            CollaborationExecutionTransferCompletion.from_dict(changed)
        changed = copy.deepcopy(completion.to_dict())
        changed["completed_at"] = "2026-07-30T10:05:01Z"
        with self.assertRaisesRegex(CollaborationPlanError, "completed time"):
            CollaborationExecutionTransferCompletion.from_dict(changed)

    def test_loader_rejects_duplicates_and_schema_accepts_exact_document(self) -> None:
        completion = self._completion()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "completion.json"
            path.write_text(json.dumps(completion.to_dict()), encoding="utf-8")
            self.assertEqual(
                load_collaboration_execution_transfer_completion(path).completion_id,
                completion.completion_id,
            )
            path.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
            with self.assertRaisesRegex(CollaborationPlanError, "Could not load"):
                load_collaboration_execution_transfer_completion(path)
        if Draft202012Validator is not None:
            Draft202012Validator(json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))).validate(
                completion.to_dict()
            )

    def test_module_has_no_runtime_storage_or_network_imports(self) -> None:
        tree = ast.parse(
            (ROOT / "src/sunderkey/collaboration_execution_transfer_completion.py").read_text(
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

"""Phase 112 fail-closed execution timeout contract coverage."""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from sunderkey.collaboration_execution_timeout import (
    CollaborationExecutionTimeoutResolution,
    build_collaboration_execution_timeout_resolution,
    collaboration_execution_timeout_resolution_selection_sha256,
    load_collaboration_execution_timeout_resolution,
    validate_collaboration_execution_timeout_resolution,
)
from sunderkey.errors import CollaborationPlanError

from . import test_collaboration_execution_transfer_authentication_phase111 as phase111

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "registry/schemas/collaboration-execution-timeout-resolution-v1.schema.json"


def control_binding(marker: str) -> dict[str, str]:
    return {
        "profile_id": "AOE-HQ-14",
        "assertion_id": "PAS-" + marker * 32,
        "assertion_sha256": "sha256:" + marker.lower() * 64,
    }


class CollaborationExecutionTimeoutPhase112Tests(unittest.TestCase):
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

    def _resolution(self, observed=None, *, binding=None, resolved_at=None):
        return build_collaboration_execution_timeout_resolution(
            authenticated_request=self.fixture.authenticated_request,
            observed_acknowledgements=[] if observed is None else observed,
            decision_owner=binding or control_binding("A"),
            resolved_at=resolved_at or "2026-07-30T10:09:01Z",
        )

    def test_no_acknowledgements_fences_source_and_blocks_successor(self) -> None:
        resolution = self._resolution()
        document = resolution.to_dict()
        self.assertEqual(
            document["missing_acknowledgement_kinds"],
            ["source_released", "target_accepted"],
        )
        self.assertEqual(
            document["source_session_disposition"],
            "fenced_pending_recovery",
        )
        self.assertEqual(
            document["target_session_disposition"],
            "blocked_never_activated",
        )
        self.assertTrue(document["recovery_required"])
        self.assertEqual(document["runtime_effect"], "none")

    def test_partial_source_release_preserves_revocation_and_requires_recovery(self) -> None:
        observed = [(self.source_authentication, self.source_session)]
        resolution = self._resolution(observed)
        document = resolution.to_dict()
        self.assertEqual(document["missing_acknowledgement_kinds"], ["target_accepted"])
        self.assertEqual(document["source_session_disposition"], "revoked_unavailable")
        self.assertEqual(
            document["observed_acknowledgements"][0]["authentication_id"],
            self.source_authentication.authentication_id,
        )
        validated = validate_collaboration_execution_timeout_resolution(
            resolution,
            authenticated_request=self.fixture.authenticated_request,
            observed_acknowledgements=observed,
        )
        self.assertEqual(validated.resolution_id, resolution.resolution_id)

    def test_complete_set_and_premature_resolution_fail_closed(self) -> None:
        with self.assertRaisesRegex(CollaborationPlanError, "cannot time out"):
            self._resolution(
                [
                    (self.source_authentication, self.source_session),
                    (self.target_authentication, self.target_session),
                ]
            )
        with self.assertRaisesRegex(CollaborationPlanError, "before its deadline"):
            self._resolution(resolved_at="2026-07-30T10:09:00Z")

    def test_duplicate_and_stale_acknowledgement_custody_fail_closed(self) -> None:
        duplicate = [
            (self.source_authentication, self.source_session),
            (self.source_authentication, self.source_session),
        ]
        with self.assertRaisesRegex(CollaborationPlanError, "duplicated"):
            self._resolution(duplicate)
        resolution = self._resolution([(self.source_authentication, self.source_session)])
        with self.assertRaisesRegex(CollaborationPlanError, "custody is stale"):
            validate_collaboration_execution_timeout_resolution(
                resolution,
                authenticated_request=self.fixture.authenticated_request,
                observed_acknowledgements=[(self.target_authentication, self.target_session)],
            )

    def test_selection_digest_excludes_only_control_assertion_binding(self) -> None:
        first = self._resolution(binding=control_binding("A"))
        second = self._resolution(binding=control_binding("B"))
        self.assertEqual(
            collaboration_execution_timeout_resolution_selection_sha256(first),
            collaboration_execution_timeout_resolution_selection_sha256(second),
        )
        changed = self._resolution(resolved_at="2026-07-30T10:09:02Z")
        self.assertNotEqual(
            collaboration_execution_timeout_resolution_selection_sha256(first),
            collaboration_execution_timeout_resolution_selection_sha256(changed),
        )

    def test_hash_loader_and_schema_are_strict(self) -> None:
        resolution = self._resolution([(self.source_authentication, self.source_session)])
        changed = copy.deepcopy(resolution.to_dict())
        changed["resolved_at"] = "2026-07-30T10:09:02Z"
        with self.assertRaisesRegex(CollaborationPlanError, "hash"):
            CollaborationExecutionTimeoutResolution.from_dict(changed)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "resolution.json"
            path.write_text(json.dumps(resolution.to_dict()), encoding="utf-8")
            self.assertEqual(
                load_collaboration_execution_timeout_resolution(path).resolution_id,
                resolution.resolution_id,
            )
            path.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
            with self.assertRaisesRegex(CollaborationPlanError, "Could not load"):
                load_collaboration_execution_timeout_resolution(path)
        if Draft202012Validator is not None:
            Draft202012Validator(json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))).validate(
                resolution.to_dict()
            )


if __name__ == "__main__":
    unittest.main()

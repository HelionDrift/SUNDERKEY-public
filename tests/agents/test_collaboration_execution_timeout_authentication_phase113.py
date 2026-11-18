"""Phase 113 independent Control timeout authentication coverage."""

from __future__ import annotations

import ast
import json
import unittest
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from sunderkey.collaboration_execution_timeout import (
    collaboration_execution_timeout_resolution_selection_sha256,
)
from sunderkey.collaboration_execution_timeout_authentication import (
    authenticate_collaboration_execution_timeout_resolution,
    validate_authenticated_collaboration_execution_timeout_resolution,
)
from sunderkey.errors import PrincipalAuthenticationError
from sunderkey.identity import PrincipalOperation, compute_operation_intent_hash

from . import test_collaboration_execution_timeout_phase112 as phase112
from .test_identity_phase4 import (
    AUDIENCE,
    MISSION_ID,
    OTHER_PROFILE_ID,
    STORE_ID,
    SUBJECT,
)

ROOT = Path(__file__).resolve().parents[2]
AUTH_SCHEMA_PATH = (
    ROOT / "registry/schemas/collaboration-execution-timeout-authentication-v1.schema.json"
)
RESOLUTION_SCHEMA_PATH = (
    ROOT / "registry/schemas/collaboration-execution-timeout-resolution-v1.schema.json"
)
CONTROL_PROFILE_ID = "AOE-HQ-14"
CONTROL_GRANT_ID = "SGR-" + "B" * 32
CONTROL_ASSERTION_ID = "PAS-" + "B" * 32
OPERATION = PrincipalOperation.EXECUTION_TIMEOUT_RESOLVE
NOW = datetime(2026, 7, 30, 10, 9, 2, tzinfo=UTC)
DIGEST_A = "sha256:" + "a" * 64


def assertion_binding(assertion) -> dict[str, str]:
    return {
        "profile_id": assertion.profile_id,
        "assertion_id": assertion.assertion_id,
        "assertion_sha256": assertion.content_sha256,
    }


class CollaborationExecutionTimeoutAuthenticationPhase113Tests(unittest.TestCase):
    def setUp(self) -> None:
        fixture = phase112.CollaborationExecutionTimeoutPhase112Tests(methodName="runTest")
        fixture.setUpClass()
        fixture.setUp()
        self.fixture = fixture
        self.observed = [(fixture.source_authentication, fixture.source_session)]
        factory = fixture.fixture.factory
        self.control_grant = factory.grant(
            grant_id=CONTROL_GRANT_ID,
            profile_id=CONTROL_PROFILE_ID,
            mission_id=MISSION_ID,
            operations=[OPERATION.value],
        )
        self.control_scope = factory.verify_grant(
            self.control_grant,
            fixture.fixture.verified_policy,
            expected_operation=OPERATION,
        )
        provisional = fixture._resolution(
            self.observed,
            binding=phase112.control_binding("C"),
        )
        intent = {
            "mission_id": MISSION_ID,
            "principal_profile_id": CONTROL_PROFILE_ID,
            "resolution_selection_sha256": (
                collaboration_execution_timeout_resolution_selection_sha256(provisional)
            ),
        }
        self.control_assertion = factory.assertion(
            grant=self.control_grant,
            assertion_id=CONTROL_ASSERTION_ID,
            scope_grant_id=CONTROL_GRANT_ID,
            subject=SUBJECT,
            profile_id=CONTROL_PROFILE_ID,
            mission_id=MISSION_ID,
            operation=OPERATION,
            operation_intent_sha256=compute_operation_intent_hash(
                OPERATION,
                intent,
            ),
            issued_at="2026-07-30T10:09:01Z",
            not_before="2026-07-30T10:09:01Z",
            expires_at="2026-07-30T10:14:01Z",
        )
        self.resolution = fixture._resolution(
            self.observed,
            binding=assertion_binding(self.control_assertion),
        )

    def _authenticate(self, **overrides):
        arguments = {
            "authenticated_request": self.fixture.fixture.authenticated_request,
            "observed_acknowledgements": self.observed,
            "independent_control_assertion": self.control_assertion,
            "verified_policy": self.fixture.fixture.verified_policy,
            "independent_control_scope": self.control_scope,
            "expected_audience": AUDIENCE,
            "expected_store_id": STORE_ID,
            "expected_control_profile_ids": [CONTROL_PROFILE_ID],
            "clock": lambda: NOW,
        }
        arguments.update(overrides)
        return authenticate_collaboration_execution_timeout_resolution(
            self.resolution,
            **arguments,
        )

    def test_independent_control_authenticates_exact_timeout_selection(self) -> None:
        authenticated = self._authenticate()
        document = authenticated.to_dict()
        self.assertEqual(document["independent_control"]["profile_id"], CONTROL_PROFILE_ID)
        self.assertEqual(
            document["authentication_status"],
            "authenticated_fail_closed_timeout",
        )
        self.assertEqual(document["runtime_effect"], "none")
        self.assertTrue(document["authentication_id"].startswith("ETA-"))
        self.assertEqual(
            validate_authenticated_collaboration_execution_timeout_resolution(authenticated),
            authenticated,
        )

    def test_control_membership_binding_and_time_fail_closed(self) -> None:
        with self.assertRaisesRegex(PrincipalAuthenticationError, "independent Control"):
            self._authenticate(expected_control_profile_ids=["AOE-HQ-15"])
        with self.assertRaisesRegex(PrincipalAuthenticationError, "not yet valid"):
            self._authenticate(clock=lambda: datetime(2026, 7, 30, 10, 9, tzinfo=UTC))
        changed = self.fixture._resolution(
            self.observed,
            binding=phase112.control_binding("D"),
        )
        with self.assertRaisesRegex(PrincipalAuthenticationError, "binding"):
            authenticate_collaboration_execution_timeout_resolution(
                changed,
                authenticated_request=self.fixture.fixture.authenticated_request,
                observed_acknowledgements=self.observed,
                independent_control_assertion=self.control_assertion,
                verified_policy=self.fixture.fixture.verified_policy,
                independent_control_scope=self.control_scope,
                expected_audience=AUDIENCE,
                expected_store_id=STORE_ID,
                expected_control_profile_ids=[CONTROL_PROFILE_ID],
                clock=lambda: NOW,
            )

    def test_authenticated_wrapper_rejects_direct_replacement(self) -> None:
        with self.assertRaises(TypeError):
            replace(self._authenticate(), authentication_sha256=DIGEST_A)

    def test_control_must_be_distinct_from_execution_participants(self) -> None:
        factory = self.fixture.fixture.factory
        grant_id = "SGR-" + "C" * 32
        assertion_id = "PAS-" + "C" * 32
        grant = factory.grant(
            grant_id=grant_id,
            profile_id=OTHER_PROFILE_ID,
            mission_id=MISSION_ID,
            operations=[OPERATION.value],
        )
        scope = factory.verify_grant(
            grant,
            self.fixture.fixture.verified_policy,
            expected_operation=OPERATION,
        )
        intent = {
            "mission_id": MISSION_ID,
            "principal_profile_id": OTHER_PROFILE_ID,
            "resolution_selection_sha256": (
                collaboration_execution_timeout_resolution_selection_sha256(self.resolution)
            ),
        }
        assertion = factory.assertion(
            grant=grant,
            assertion_id=assertion_id,
            scope_grant_id=grant_id,
            subject=SUBJECT,
            profile_id=OTHER_PROFILE_ID,
            mission_id=MISSION_ID,
            operation=OPERATION,
            operation_intent_sha256=compute_operation_intent_hash(
                OPERATION,
                intent,
            ),
            issued_at="2026-07-30T10:09:01Z",
            not_before="2026-07-30T10:09:01Z",
            expires_at="2026-07-30T10:14:01Z",
        )
        resolution = self.fixture._resolution(
            self.observed,
            binding=assertion_binding(assertion),
        )
        with self.assertRaisesRegex(PrincipalAuthenticationError, "distinct"):
            authenticate_collaboration_execution_timeout_resolution(
                resolution,
                authenticated_request=self.fixture.fixture.authenticated_request,
                observed_acknowledgements=self.observed,
                independent_control_assertion=assertion,
                verified_policy=self.fixture.fixture.verified_policy,
                independent_control_scope=scope,
                expected_audience=AUDIENCE,
                expected_store_id=STORE_ID,
                expected_control_profile_ids=[OTHER_PROFILE_ID],
                clock=lambda: NOW,
            )

    def test_authentication_matches_schema(self) -> None:
        if Draft202012Validator is not None:
            schema = json.loads(AUTH_SCHEMA_PATH.read_text(encoding="utf-8"))
            schema["properties"]["timeout_resolution"] = json.loads(
                RESOLUTION_SCHEMA_PATH.read_text(encoding="utf-8")
            )
            Draft202012Validator(schema).validate(self._authenticate().to_dict())

    def test_module_has_no_network_storage_or_execution_imports(self) -> None:
        tree = ast.parse(
            (ROOT / "src/sunderkey/collaboration_execution_timeout_authentication.py").read_text(
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
            str(node.module).split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
        )
        self.assertFalse(
            imported & {"asyncio", "http", "requests", "socket", "sqlite3", "subprocess", "urllib"}
        )


if __name__ == "__main__":
    unittest.main()

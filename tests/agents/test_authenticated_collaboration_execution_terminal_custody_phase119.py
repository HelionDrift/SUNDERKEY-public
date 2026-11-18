"""Phase 119 atomic execution terminal custody coverage."""

from __future__ import annotations

import json
import sqlite3
import unittest
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from sunderkey.authenticated_collaboration_execution_terminal_custody import (
    AuthenticatedCollaborationExecutionTerminalCustodyService,
)
from sunderkey.collaboration_execution_channel import (
    build_collaboration_fenced_worker_session,
)
from sunderkey.collaboration_execution_terminal_custody import (
    build_collaboration_execution_terminal_custody_plan,
)
from sunderkey.collaboration_execution_timeout import (
    build_collaboration_execution_timeout_resolution,
    collaboration_execution_timeout_resolution_selection_sha256,
)
from sunderkey.collaboration_execution_timeout_authentication import (
    authenticate_collaboration_execution_timeout_resolution,
)
from sunderkey.collaboration_execution_transfer import (
    build_collaboration_execution_acknowledgement,
    build_collaboration_execution_transfer_request,
    collaboration_execution_acknowledgement_selection_sha256,
    collaboration_execution_transfer_request_selection_sha256,
)
from sunderkey.collaboration_execution_transfer_authentication import (
    authenticate_collaboration_execution_acknowledgement,
    authenticate_collaboration_execution_transfer_request,
)
from sunderkey.collaboration_execution_transfer_completion import (
    build_collaboration_execution_transfer_completion,
)
from sunderkey.collaboration_ownership_chain import (
    collaboration_work_item_objective_sha256,
)
from sunderkey.errors import PrincipalAuthenticationError, StoreConflictError
from sunderkey.identity import PrincipalOperation, compute_operation_intent_hash
from sunderkey.store import canonical_json, sha256_text

from . import test_authenticated_collaboration_execution_channel_phase109 as phase109
from .test_identity_phase4 import AUDIENCE, SUBJECT

ROOT = Path(__file__).resolve().parents[2]
RECEIPT_SCHEMA_PATH = (
    ROOT
    / "registry/schemas/collaboration-execution-terminal-custody-commit-receipt-v1.schema.json"
)
PLAN_SCHEMA_PATH = (
    ROOT / "registry/schemas/collaboration-execution-terminal-custody-plan-v1.schema.json"
)
SOURCE_ID = "AOE-HQ-09"
TARGET_ID = "AOE-HQ-10"
TIMEOUT_CONTROL_ID = phase109.CONTROL_ID
REQUEST_GRANT_ID = "SGR-" + "11" * 16
SOURCE_GRANT_ID = "SGR-" + "12" * 16
TARGET_GRANT_ID = "SGR-" + "13" * 16
TIMEOUT_CONTROL_GRANT_ID = "SGR-" + "14" * 16
REQUEST_ASSERTION_ID = "PAS-" + "11" * 16
SOURCE_ASSERTION_ID = "PAS-" + "12" * 16
TARGET_ASSERTION_ID = "PAS-" + "13" * 16
TIMEOUT_CONTROL_ASSERTION_ID = "PAS-" + "14" * 16
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64
DIGEST_C = "sha256:" + "c" * 64


class AuthenticatedCollaborationExecutionTerminalCustodyPhase119Tests(
    unittest.TestCase
):
    def setUp(self) -> None:
        fixture = phase109.AuthenticatedCollaborationExecutionChannelPhase109Tests(
            methodName="runTest"
        )
        phase109.AuthenticatedCollaborationExecutionChannelPhase109Tests.setUpClass()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        self.channel_receipt = fixture._commit()
        fixture.fixture.now = datetime(2026, 7, 30, 10, 6, 1, tzinfo=UTC)
        operations = [
            PrincipalOperation.COLLABORATION_ACTIVATE.value,
            PrincipalOperation.COLLABORATION_POLICY_CONTROL_APPROVE.value,
            PrincipalOperation.COLLABORATION_POLICY_OWNER_AUTHORIZE.value,
            PrincipalOperation.EXECUTION_CHANNEL_POLICY_CONTROL_APPROVE.value,
            PrincipalOperation.EXECUTION_CHANNEL_POLICY_OWNER_AUTHORIZE.value,
            PrincipalOperation.EXECUTION_TRANSFER_ACKNOWLEDGE.value,
            PrincipalOperation.EXECUTION_TRANSFER_REQUEST_AUTHORIZE.value,
            PrincipalOperation.EXECUTION_TIMEOUT_RESOLVE.value,
        ]
        policy = fixture.fixture.factory.policy(
            max_assertion_lifetime_seconds=900,
            policy_version=phase109.POLICY_VERSION + 2,
            store_id=fixture.fixture.store_id,
            allowed_profiles=[
                phase109.OWNER_ID,
                phase109.CONTROL_ID,
                SOURCE_ID,
                TARGET_ID,
            ],
            allowed_operations=operations,
        )
        fixture.fixture.trust.apply_policy(policy)
        with fixture.fixture.store._read_connection() as connection:
            identity = fixture.fixture.store._verify_store_identity(
                connection,
                verify_history=False,
            )
            policies = fixture.fixture.store._verify_trust_policy_history(
                connection,
                identity,
            )
            self.verified_policy = policies[str(identity["trust_policy_hash"])]
        self.request_grant = self._grant(
            REQUEST_GRANT_ID,
            phase109.OWNER_ID,
            PrincipalOperation.EXECUTION_TRANSFER_REQUEST_AUTHORIZE,
        )
        self.source_grant = self._grant(
            SOURCE_GRANT_ID,
            SOURCE_ID,
            PrincipalOperation.EXECUTION_TRANSFER_ACKNOWLEDGE,
        )
        self.target_grant = self._grant(
            TARGET_GRANT_ID,
            TARGET_ID,
            PrincipalOperation.EXECUTION_TRANSFER_ACKNOWLEDGE,
        )
        self.timeout_control_grant = self._grant(
            TIMEOUT_CONTROL_GRANT_ID,
            TIMEOUT_CONTROL_ID,
            PrincipalOperation.EXECUTION_TIMEOUT_RESOLVE,
        )
        for grant in (
            self.request_grant,
            self.source_grant,
            self.target_grant,
            self.timeout_control_grant,
        ):
            fixture.fixture.acceptance.accept(grant)
        self.request_scope = self._verified_scope(
            self.request_grant,
            PrincipalOperation.EXECUTION_TRANSFER_REQUEST_AUTHORIZE,
        )
        self.source_scope = self._verified_scope(
            self.source_grant,
            PrincipalOperation.EXECUTION_TRANSFER_ACKNOWLEDGE,
        )
        self.target_scope = self._verified_scope(
            self.target_grant,
            PrincipalOperation.EXECUTION_TRANSFER_ACKNOWLEDGE,
        )
        self.timeout_control_scope = self._verified_scope(
            self.timeout_control_grant,
            PrincipalOperation.EXECUTION_TIMEOUT_RESOLVE,
        )
        item = fixture.fixture.plan.work_items[0]
        objective_sha256 = collaboration_work_item_objective_sha256(item)
        self.source_session = build_collaboration_fenced_worker_session(
            channel_policy=fixture.policy,
            work_item_id=item.work_item_id,
            work_item_objective_sha256=objective_sha256,
            ownership_chain_id="OCN-" + "1" * 32,
            ownership_entry_id="OCE-" + "2" * 32,
            ownership_entry_sha256=DIGEST_A,
            owner_profile_id=SOURCE_ID,
            owner_epoch=1,
            worker_principal_id=SOURCE_ID,
            fence_generation=1,
            credential_reference_id="CREDENTIAL-PHASE119-SOURCE",
            credential_sha256=DIGEST_B,
            predecessor=None,
            prepared_at="2026-07-30T10:05:10Z",
            expires_at="2026-07-30T10:30:00Z",
        )
        source = self.source_session.to_dict()
        self.target_session = build_collaboration_fenced_worker_session(
            channel_policy=fixture.policy,
            work_item_id=item.work_item_id,
            work_item_objective_sha256=objective_sha256,
            ownership_chain_id=source["ownership_chain_id"],
            ownership_entry_id="OCE-" + "3" * 32,
            ownership_entry_sha256=DIGEST_B,
            owner_profile_id=TARGET_ID,
            owner_epoch=2,
            worker_principal_id=TARGET_ID,
            fence_generation=2,
            credential_reference_id="CREDENTIAL-PHASE119-TARGET",
            credential_sha256=DIGEST_C,
            predecessor={
                "session_id": self.source_session.session_id,
                "session_sha256": self.source_session.session_sha256,
                "credential_reference_id": source["credential_reference_id"],
                "credential_sha256": source["credential_sha256"],
                "revocation_reference_id": "REVOCATION-PHASE119-SOURCE",
                "revocation_sha256": DIGEST_C,
            },
            prepared_at="2026-07-30T10:05:20Z",
            expires_at="2026-07-30T10:30:00Z",
        )
        provisional_request = self._request(self._placeholder(phase109.OWNER_ID, "4"))
        request_intent = {
            "mission_id": phase109.MISSION_ID,
            "principal_profile_id": phase109.OWNER_ID,
            "request_selection_sha256": (
                collaboration_execution_transfer_request_selection_sha256(
                    provisional_request
                )
            ),
        }
        self.request_assertion = self._assertion(
            self.request_grant,
            REQUEST_ASSERTION_ID,
            phase109.OWNER_ID,
            PrincipalOperation.EXECUTION_TRANSFER_REQUEST_AUTHORIZE,
            request_intent,
        )
        self.request = self._request(self._binding(self.request_assertion))
        self.authenticated_request = authenticate_collaboration_execution_transfer_request(
            self.request,
            requester_assertion=self.request_assertion,
            verified_policy=self.verified_policy,
            requester_scope=self.request_scope,
            expected_audience=AUDIENCE,
            expected_store_id=fixture.fixture.store_id,
            clock=lambda: fixture.fixture.now,
        )
        fixture.fixture.now = datetime(2026, 7, 30, 10, 6, 40, tzinfo=UTC)
        self.source_authentication, self.source_assertion = self._acknowledgement(
            "source_released"
        )
        self.target_authentication, self.target_assertion = self._acknowledgement(
            "target_accepted"
        )
        self.acknowledgements = [
            (self.source_authentication, self.source_session),
            (self.target_authentication, self.target_session),
        ]
        self.completion = build_collaboration_execution_transfer_completion(
            authenticated_request=self.authenticated_request,
            acknowledgements=self.acknowledgements,
        )
        self.plan = build_collaboration_execution_terminal_custody_plan(
            authenticated_request=self.authenticated_request,
            acknowledgements=self.acknowledgements,
            completion=self.completion,
        )
        self.assertions = [
            self.request_assertion,
            self.source_assertion,
            self.target_assertion,
        ]
        fixture.fixture.now = datetime(2026, 7, 30, 10, 7, tzinfo=UTC)
        self.service = AuthenticatedCollaborationExecutionTerminalCustodyService(
            fixture.fixture.store,
            fixture.fixture.registry,
            clock=lambda: fixture.fixture.now,
        )

    def _grant(self, grant_id: str, profile_id: str, operation: PrincipalOperation):
        root = self.fixture.fixture
        return root.factory.grant(
            grant_id=grant_id,
            profile_id=profile_id,
            store_id=root.store_id,
            mission_id=phase109.MISSION_ID,
            mission_context_hash=root.stored.context_hash,
            scope_reference=root.mission.scope_reference,
            scope_document_hash=root.mission.scope_document_hash,
            environment=root.mission.environment.value,
            max_action_tier=root.mission.max_action_tier.value,
            constraints_hash=sha256_text(
                canonical_json(root.mission.to_dict()["constraints"])
            ),
            operations=[operation.value],
            policy_version=phase109.POLICY_VERSION + 2,
        )

    def _verified_scope(self, grant, operation: PrincipalOperation):
        root = self.fixture.fixture
        return root.factory.verify_grant(
            grant,
            self.verified_policy,
            expected_store_id=root.store_id,
            expected_mission_id=phase109.MISSION_ID,
            expected_mission_context_hash=root.stored.context_hash,
            expected_scope_reference=root.mission.scope_reference,
            expected_scope_document_hash=root.mission.scope_document_hash,
            expected_environment=root.mission.environment.value,
            expected_max_action_tier=root.mission.max_action_tier.value,
            expected_constraints_hash=sha256_text(
                canonical_json(root.mission.to_dict()["constraints"])
            ),
            expected_operation=operation,
            clock=lambda: self.fixture.fixture.now,
        )

    def _assertion(
        self,
        grant,
        assertion_id: str,
        profile_id: str,
        operation: PrincipalOperation,
        intent: dict[str, str],
    ):
        return self.fixture.fixture.factory.assertion(
            grant=grant,
            assertion_id=assertion_id,
            policy_version=phase109.POLICY_VERSION + 2,
            scope_grant_id=grant.grant_id,
            subject=SUBJECT,
            profile_id=profile_id,
            audience=AUDIENCE,
            store_id=self.fixture.fixture.store_id,
            mission_id=phase109.MISSION_ID,
            operation=operation,
            operation_intent_sha256=compute_operation_intent_hash(operation, intent),
            issued_at="2026-07-30T10:06:00Z",
            not_before="2026-07-30T10:06:00Z",
            expires_at="2026-07-30T10:15:00Z",
        )

    def _request(self, binding: dict[str, str]):
        return build_collaboration_execution_transfer_request(
            channel_policy=self.fixture.policy,
            source_session=self.source_session,
            target_session=self.target_session,
            transfer_kind="ownership_handoff",
            control_transition_id="OCE-" + "3" * 32,
            control_transition_sha256=DIGEST_B,
            control_plane_requester=binding,
            requested_at="2026-07-30T10:06:00Z",
        )

    def _acknowledgement(self, kind: str):
        source = kind == "source_released"
        profile_id = SOURCE_ID if source else TARGET_ID
        grant = self.source_grant if source else self.target_grant
        assertion_id = SOURCE_ASSERTION_ID if source else TARGET_ASSERTION_ID
        session = self.source_session if source else self.target_session
        provisional = build_collaboration_execution_acknowledgement(
            request=self.request,
            acknowledgement_kind=kind,
            session=session,
            external_acknowledger=self._placeholder(profile_id, "5" if source else "6"),
            revocation_reference_id="REVOCATION-PHASE119-FINAL" if source else None,
            revocation_sha256=DIGEST_C if source else None,
            acknowledged_at=(
                "2026-07-30T10:06:20Z" if source else "2026-07-30T10:06:30Z"
            ),
        )
        intent = {
            "acknowledgement_selection_sha256": (
                collaboration_execution_acknowledgement_selection_sha256(provisional)
            ),
            "mission_id": phase109.MISSION_ID,
            "principal_profile_id": profile_id,
            "request_id": self.request.request_id,
            "request_sha256": self.request.request_sha256,
        }
        assertion = self._assertion(
            grant,
            assertion_id,
            profile_id,
            PrincipalOperation.EXECUTION_TRANSFER_ACKNOWLEDGE,
            intent,
        )
        acknowledgement = build_collaboration_execution_acknowledgement(
            request=self.request,
            acknowledgement_kind=kind,
            session=session,
            external_acknowledger=self._binding(assertion),
            revocation_reference_id="REVOCATION-PHASE119-FINAL" if source else None,
            revocation_sha256=DIGEST_C if source else None,
            acknowledged_at=(
                "2026-07-30T10:06:20Z" if source else "2026-07-30T10:06:30Z"
            ),
        )
        authenticated = authenticate_collaboration_execution_acknowledgement(
            acknowledgement,
            authenticated_request=self.authenticated_request,
            session=session,
            acknowledger_assertion=assertion,
            verified_policy=self.verified_policy,
            acknowledger_scope=self.source_scope if source else self.target_scope,
            expected_audience=AUDIENCE,
            expected_store_id=self.fixture.fixture.store_id,
            clock=lambda: self.fixture.fixture.now,
        )
        return authenticated, assertion

    @staticmethod
    def _placeholder(profile_id: str, marker: str) -> dict[str, str]:
        return {
            "profile_id": profile_id,
            "assertion_id": "PAS-" + marker * 32,
            "assertion_sha256": "sha256:" + marker.lower() * 64,
        }

    @staticmethod
    def _binding(assertion) -> dict[str, str]:
        return {
            "profile_id": assertion.profile_id,
            "assertion_id": assertion.assertion_id,
            "assertion_sha256": assertion.content_sha256,
        }

    def _commit(self):
        return self.service.commit(
            self.plan,
            authenticated_request=self.authenticated_request,
            acknowledgements=self.acknowledgements,
            participant_assertions=self.assertions,
            completion=self.completion,
        )

    def test_commit_is_atomic_durable_and_exactly_replayable(self) -> None:
        receipt = self._commit()
        self.fixture.fixture.now = datetime(2026, 7, 30, 10, 20, tzinfo=UTC)
        self.assertEqual(self._commit(), receipt)
        self.assertEqual(receipt.to_dict()["commit_status"], "committed_terminal_custody")
        self.assertEqual(receipt.to_dict()["runtime_effect"], "none")
        self.assertEqual(
            [item.role for item in receipt.participant_commits],
            ["control_plane_requester", "source_worker", "target_worker"],
        )
        with closing(sqlite3.connect(self.fixture.fixture.path)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM execution_terminal_custody_commits"
                ).fetchone()[0],
                1,
            )
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM execution_terminal_custody_participants"
                ).fetchone()[0],
                3,
            )
        report = self.fixture.fixture.store.verify_store(self.fixture.fixture.registry)
        self.assertEqual(report.status, "valid")

    def test_get_is_read_only_and_receipt_matches_schema(self) -> None:
        with self.assertRaisesRegex(StoreConflictError, "not committed"):
            self.service.get(self.plan.custody_plan_id)
        receipt = self._commit()
        self.assertEqual(self.service.get(self.plan.custody_plan_id), receipt)
        if Draft202012Validator is not None:
            schema = json.loads(RECEIPT_SCHEMA_PATH.read_text(encoding="utf-8"))
            schema["properties"]["custody_plan"] = json.loads(
                PLAN_SCHEMA_PATH.read_text(encoding="utf-8")
            )
            Draft202012Validator(schema).validate(receipt.to_dict())

    def test_fail_closed_timeout_commits_control_last(self) -> None:
        observed = [(self.source_authentication, self.source_session)]
        provisional = build_collaboration_execution_timeout_resolution(
            authenticated_request=self.authenticated_request,
            observed_acknowledgements=observed,
            decision_owner=self._placeholder(TIMEOUT_CONTROL_ID, "7"),
            resolved_at="2026-07-30T10:11:01Z",
        )
        intent = {
            "mission_id": phase109.MISSION_ID,
            "principal_profile_id": TIMEOUT_CONTROL_ID,
            "resolution_selection_sha256": (
                collaboration_execution_timeout_resolution_selection_sha256(provisional)
            ),
        }
        control_assertion = self._assertion(
            self.timeout_control_grant,
            TIMEOUT_CONTROL_ASSERTION_ID,
            TIMEOUT_CONTROL_ID,
            PrincipalOperation.EXECUTION_TIMEOUT_RESOLVE,
            intent,
        )
        resolution = build_collaboration_execution_timeout_resolution(
            authenticated_request=self.authenticated_request,
            observed_acknowledgements=observed,
            decision_owner=self._binding(control_assertion),
            resolved_at="2026-07-30T10:11:01Z",
        )
        self.fixture.fixture.now = datetime(2026, 7, 30, 10, 11, 2, tzinfo=UTC)
        authenticated_timeout = authenticate_collaboration_execution_timeout_resolution(
            resolution,
            authenticated_request=self.authenticated_request,
            observed_acknowledgements=observed,
            independent_control_assertion=control_assertion,
            verified_policy=self.verified_policy,
            independent_control_scope=self.timeout_control_scope,
            expected_audience=AUDIENCE,
            expected_store_id=self.fixture.fixture.store_id,
            expected_control_profile_ids=self.fixture.fixture.stored.control_profile_ids,
            clock=lambda: self.fixture.fixture.now,
        )
        plan = build_collaboration_execution_terminal_custody_plan(
            authenticated_request=self.authenticated_request,
            acknowledgements=observed,
            authenticated_timeout=authenticated_timeout,
        )
        receipt = self.service.commit(
            plan,
            authenticated_request=self.authenticated_request,
            acknowledgements=observed,
            participant_assertions=[
                self.request_assertion,
                self.source_assertion,
                control_assertion,
            ],
            authenticated_timeout=authenticated_timeout,
        )
        document = receipt.to_dict()
        self.assertEqual(
            document["custody_plan"]["terminal_kind"],
            "failed_closed_timeout",
        )
        self.assertTrue(document["custody_plan"]["recovery_required"])
        self.assertEqual(
            [item["role"] for item in document["participant_commits"]],
            ["control_plane_requester", "source_worker", "independent_control"],
        )
        self.assertEqual(
            self.fixture.fixture.store.verify_store(self.fixture.fixture.registry).status,
            "valid",
        )

    def test_mismatched_assertion_fails_before_consumption(self) -> None:
        with self.assertRaisesRegex(PrincipalAuthenticationError, "does not match"):
            self.service.commit(
                self.plan,
                authenticated_request=self.authenticated_request,
                acknowledgements=self.acknowledgements,
                participant_assertions=[
                    self.source_assertion,
                    self.request_assertion,
                    self.target_assertion,
                ],
                completion=self.completion,
            )
        with closing(sqlite3.connect(self.fixture.fixture.path)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM execution_terminal_custody_commits"
                ).fetchone()[0],
                0,
            )

    def test_late_storage_failure_rolls_back_every_assertion(self) -> None:
        with patch.object(
            self.service,
            "_insert_participants",
            side_effect=sqlite3.IntegrityError("injected participant failure"),
        ), self.assertRaisesRegex(StoreConflictError, "Could not commit"):
            self._commit()
        with closing(sqlite3.connect(self.fixture.fixture.path)) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT COUNT(*) FROM execution_terminal_custody_commits"
                ).fetchone()[0],
                0,
            )
            self.assertEqual(
                connection.execute(
                    """
                    SELECT COUNT(*) FROM principal_assertion_uses
                    WHERE operation IN (?, ?)
                    """,
                    (
                        PrincipalOperation.EXECUTION_TRANSFER_REQUEST_AUTHORIZE.value,
                        PrincipalOperation.EXECUTION_TRANSFER_ACKNOWLEDGE.value,
                    ),
                ).fetchone()[0],
                0,
            )


if __name__ == "__main__":
    unittest.main()

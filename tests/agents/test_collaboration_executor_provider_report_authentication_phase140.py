"""Phase 140 authenticated provider-report contract coverage."""

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
from sunderkey.collaboration_executor_authentication import (
    authenticate_collaboration_executor_acknowledgement,
    collaboration_executor_acknowledgement_selection_sha256,
)
from sunderkey.collaboration_executor_provider_report import (
    build_collaboration_executor_provider_report,
)
from sunderkey.collaboration_executor_provider_report_authentication import (
    AuthenticatedCollaborationExecutorProviderReport,
    bind_authenticated_collaboration_executor_provider_report,
    collaboration_executor_provider_report_authentication_effect_payload,
    validate_authenticated_collaboration_executor_provider_report_document,
)
from sunderkey.errors import CollaborationPlanError
from sunderkey.identity import (
    PrincipalOperation,
    compute_operation_intent_hash,
    verify_trust_policy,
)
from sunderkey.store import canonical_json, sha256_text

from . import test_collaboration_executor_invocation_attempt_phase133 as phase133
from . import test_collaboration_executor_provider_report_store_phase139 as phase139
from .test_identity_phase4 import (
    AUDIENCE,
    ROOT_KEY_ID,
    SUBJECT,
    public_bytes,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = ROOT / "registry/schemas"
POLICY_VERSION = 900140
GRANT_ID = "SGR-" + "61" * 16
ASSERTION_ID = "PAS-" + "61" * 16


class CollaborationExecutorProviderReportAuthenticationPhase140Tests(
    unittest.TestCase
):
    def setUp(self) -> None:
        fixture = phase139.CollaborationExecutorProviderReportStorePhase139Tests(
            methodName="runTest"
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        self.root = fixture.root
        self.preparation_receipt = fixture._prepare()
        self.report_receipt = fixture.service.commit(
            self.preparation_receipt.attempt_id,
            fixture._acknowledgement(),
        )
        self.report = self.report_receipt.provider_report
        self.dispatch = fixture.fixture.fixture.dispatch
        self.worker_id = self.dispatch.to_dict()["worker"]["worker_principal_id"]
        policy = self.root.factory.policy(
            max_assertion_lifetime_seconds=900,
            policy_version=POLICY_VERSION,
            store_id=self.root.store_id,
            allowed_profiles=[self.worker_id],
            allowed_operations=[PrincipalOperation.EXECUTOR_ACKNOWLEDGE.value],
        )
        self.verified_policy = verify_trust_policy(
            policy,
            {ROOT_KEY_ID: public_bytes(self.root.factory.root_private)},
            expected_audience=AUDIENCE,
            expected_store_id=self.root.store_id,
            expected_root_key_id=ROOT_KEY_ID,
            minimum_policy_version=7,
            clock=lambda: self.root.now,
        )
        self.root.trust.apply_policy(policy)
        mission = self.root.mission
        self.grant = self.root.factory.grant(
            grant_id=GRANT_ID,
            profile_id=self.worker_id,
            store_id=self.root.store_id,
            mission_id=mission.mission_id,
            mission_context_hash=self.root.stored.context_hash,
            scope_reference=mission.scope_reference,
            scope_document_hash=mission.scope_document_hash,
            environment=mission.environment.value,
            max_action_tier=mission.max_action_tier.value,
            constraints_hash=sha256_text(
                canonical_json(mission.to_dict()["constraints"])
            ),
            operations=[PrincipalOperation.EXECUTOR_ACKNOWLEDGE.value],
            policy_version=POLICY_VERSION,
            expires_at="2026-07-30T10:20:00Z",
        )
        self.root.acceptance.accept(self.grant)
        self.worker_scope = self.root.factory.verify_grant(
            self.grant,
            self.verified_policy,
            expected_audience=AUDIENCE,
            expected_store_id=self.root.store_id,
            expected_mission_id=mission.mission_id,
            expected_mission_context_hash=self.root.stored.context_hash,
            expected_scope_reference=mission.scope_reference,
            expected_scope_document_hash=mission.scope_document_hash,
            expected_environment=mission.environment.value,
            expected_max_action_tier=mission.max_action_tier.value,
            expected_constraints_hash=sha256_text(
                canonical_json(mission.to_dict()["constraints"])
            ),
            expected_operation=PrincipalOperation.EXECUTOR_ACKNOWLEDGE,
            clock=lambda: self.root.now,
        )

    def _assertion(
        self,
        acknowledgement,
        *,
        assertion_id: str = ASSERTION_ID,
    ):
        dispatch = self.dispatch.to_dict()
        intent = {
            "acknowledgement_selection_sha256": (
                collaboration_executor_acknowledgement_selection_sha256(
                    acknowledgement
                )
            ),
            "dispatch_sha256": self.dispatch.dispatch_sha256,
            "mission_id": dispatch["mission"]["mission_id"],
            "principal_profile_id": self.worker_id,
        }
        return self.root.factory.assertion(
            grant=self.grant,
            assertion_id=assertion_id,
            policy_version=POLICY_VERSION,
            scope_grant_id=self.grant.grant_id,
            subject=SUBJECT,
            profile_id=self.worker_id,
            audience=AUDIENCE,
            store_id=self.root.store_id,
            mission_id=dispatch["mission"]["mission_id"],
            operation=PrincipalOperation.EXECUTOR_ACKNOWLEDGE,
            operation_intent_sha256=compute_operation_intent_hash(
                PrincipalOperation.EXECUTOR_ACKNOWLEDGE,
                intent,
            ),
            issued_at="2026-07-30T10:08:34Z",
            not_before="2026-07-30T10:08:34Z",
            expires_at="2026-07-30T10:10:00Z",
        )

    def _authenticate(self, acknowledgement=None, *, assertion_id=ASSERTION_ID):
        selected = acknowledgement or self.report.provider_acknowledgement
        return authenticate_collaboration_executor_acknowledgement(
            self.dispatch,
            selected,
            worker_assertion=self._assertion(
                selected,
                assertion_id=assertion_id,
            ),
            verified_policy=self.verified_policy,
            worker_scope=self.worker_scope,
            expected_audience=AUDIENCE,
            expected_store_id=self.root.store_id,
            clock=lambda: self.root.now,
        )

    def _bind(self):
        return bind_authenticated_collaboration_executor_provider_report(
            self.report,
            self._authenticate(),
        )

    def test_worker_authentication_binds_exact_retained_report(self) -> None:
        authenticated = self._bind()
        document = authenticated.to_dict()
        self.assertEqual(
            document["provider_report"],
            self.report.to_dict(),
        )
        self.assertEqual(
            document["authentication_status"],
            "authenticated_worker_principal",
        )
        self.assertEqual(
            document["evidence_verification_status"],
            "provider_evidence_digest_unverified",
        )
        self.assertEqual(
            document["external_effect_status"],
            "authenticated_report_unverified_effect",
        )
        self.assertEqual(document["runtime_effect"], "none")

    def test_serialized_authentication_revalidates_without_trusted_wrapper(
        self,
    ) -> None:
        document = self._bind().to_dict()
        self.assertEqual(
            validate_authenticated_collaboration_executor_provider_report_document(
                document
            ),
            document,
        )

    def test_serialized_authentication_rejects_nested_worker_tampering(
        self,
    ) -> None:
        document = self._bind().to_dict()
        document["acknowledgement_authentication"]["worker_attestor"][
            "profile_id"
        ] = "specialist.tampered"
        with self.assertRaisesRegex(CollaborationPlanError, "worker does not match"):
            validate_authenticated_collaboration_executor_provider_report_document(
                document
            )

    def test_protected_effect_payload_names_exact_authentication(self) -> None:
        authenticated = self._bind()
        document = authenticated.to_dict()
        payload = (
            collaboration_executor_provider_report_authentication_effect_payload(
                authenticated
            )
        )
        acknowledgement = document["provider_report"][
            "provider_acknowledgement"
        ]
        authentication = document["acknowledgement_authentication"]
        self.assertEqual(
            payload,
            {
                "report_authentication_id": document[
                    "report_authentication_id"
                ],
                "report_authentication_sha256": document[
                    "report_authentication_sha256"
                ],
                "report_custody_id": document["provider_report"][
                    "report_custody_id"
                ],
                "report_custody_sha256": document["provider_report"][
                    "report_custody_sha256"
                ],
                "attempt_id": document["provider_report"][
                    "invocation_preparation"
                ]["attempt_id"],
                "acknowledgement_authentication_id": authentication[
                    "authentication_id"
                ],
                "acknowledgement_authentication_sha256": authentication[
                    "authentication_sha256"
                ],
                "acknowledgement_id": acknowledgement[
                    "acknowledgement_id"
                ],
                "acknowledgement_sha256": acknowledgement[
                    "acknowledgement_sha256"
                ],
                "mission_id": authentication["worker_attestor"][
                    "mission_id"
                ],
                "authentication_status": (
                    "authenticated_worker_principal"
                ),
                "evidence_verification_status": (
                    "provider_evidence_digest_unverified"
                ),
                "external_effect_status": (
                    "authenticated_report_unverified_effect"
                ),
                "runtime_effect": "none",
            },
        )

    def test_changed_acknowledgement_authentication_cannot_rebind(self) -> None:
        changed = build_collaboration_executor_acknowledgement(
            self.dispatch,
            adapter_id="adapter.test",
            adapter_version="1.0.0",
            adapter_build_sha256=phase133.ADAPTER_BUILD,
            runtime_instance_id="worker-runtime-1",
            outcome="accepted",
            provider_worker_state="ready",
            provider_evidence_sha256="sha256:" + "96" * 32,
            acknowledged_at="2026-07-30T10:08:34Z",
        )
        changed_authentication = self._authenticate(
            changed,
            assertion_id="PAS-" + "62" * 16,
        )
        with self.assertRaisesRegex(CollaborationPlanError, "retained report"):
            bind_authenticated_collaboration_executor_provider_report(
                self.report,
                changed_authentication,
            )

    def test_authentication_cannot_precede_report_custody(self) -> None:
        authentication = self._authenticate()
        late_report = build_collaboration_executor_provider_report(
            self.preparation_receipt.preparation,
            self.report.provider_acknowledgement,
            received_at="2026-07-30T10:08:36Z",
        )
        with self.assertRaisesRegex(CollaborationPlanError, "precedes"):
            bind_authenticated_collaboration_executor_provider_report(
                late_report,
                authentication,
            )

    def test_authenticated_wrapper_cannot_be_directly_forged(self) -> None:
        authenticated = self._bind()
        with self.assertRaisesRegex(TypeError, "only by"):
            AuthenticatedCollaborationExecutorProviderReport(
                report_authentication_id=(
                    authenticated.report_authentication_id
                ),
                report_authentication_sha256=(
                    authenticated.report_authentication_sha256
                ),
                provider_report=authenticated.provider_report,
                acknowledgement_authentication=(
                    authenticated.acknowledgement_authentication
                ),
                _proof=b"wrong",
            )

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_authentication_matches_strict_schema(self) -> None:
        acknowledgement_schema = json.loads(
            (
                SCHEMAS / "collaboration-executor-acknowledgement-v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        report_schema = json.loads(
            (
                SCHEMAS / "collaboration-executor-provider-report-v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        report_schema["properties"]["provider_acknowledgement"] = (
            acknowledgement_schema
        )
        acknowledgement_authentication_schema = json.loads(
            (
                SCHEMAS
                / "collaboration-executor-acknowledgement-authentication-v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        acknowledgement_authentication_schema["properties"][
            "acknowledgement"
        ] = acknowledgement_schema
        schema = json.loads(
            (
                SCHEMAS
                / "collaboration-executor-provider-report-authentication-v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        schema["properties"]["provider_report"] = report_schema
        schema["properties"]["acknowledgement_authentication"] = (
            acknowledgement_authentication_schema
        )
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(self._bind().to_dict())

    def test_contract_has_no_network_storage_process_or_adapter(self) -> None:
        source_path = (
            ROOT
            / "src/sunderkey/collaboration_executor_provider_report_authentication.py"
        )
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
                "sqlite3",
                "subprocess",
                "urllib",
            }
        )
        self.assertNotIn("CollaborationExecutorAdapter", source)


if __name__ == "__main__":
    unittest.main()

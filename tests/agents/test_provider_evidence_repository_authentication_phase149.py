"""Phase 149 provider evidence repository receipt authentication coverage."""

from __future__ import annotations

import ast
import copy
import hashlib
import json
import unittest
from datetime import UTC, datetime
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

from sunderkey.errors import PrincipalAuthenticationError
from sunderkey.identity import (
    PrincipalOperation,
    compute_operation_intent_hash,
    verify_trust_policy,
)
from sunderkey.provider_evidence_lifecycle import (
    ProviderEvidenceLifecyclePolicy,
    build_provider_evidence_lifecycle_policy,
)
from sunderkey.provider_evidence_repository import (
    build_provider_evidence_repository_ingest_receipt,
    build_provider_evidence_repository_ingest_request,
)
from sunderkey.provider_evidence_repository_authentication import (
    AuthenticatedProviderEvidenceRepositoryIngestReceipt,
    authenticate_provider_evidence_repository_ingest_receipt,
    provider_evidence_repository_ingest_receipt_selection_sha256,
)
from sunderkey.store import canonical_json, sha256_text
from sunderkey.qualification import _canonical_sha256

from . import test_provider_evidence_repository_phase147 as phase147
from .test_identity_phase4 import AUDIENCE, ROOT_KEY_ID, public_bytes

ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = ROOT / "registry/schemas"
POLICY_VERSION = 900149
PROFILE_ID = "AOE-HQ-12"
SUBJECT = "service:repository.synthetic-001"
GRANT_ID = "SGR-" + "96" * 16
ASSERTION_ID = "PAS-" + "96" * 16


class ProviderEvidenceRepositoryAuthenticationPhase149Tests(unittest.TestCase):
    def setUp(self) -> None:
        fixture = phase147.ProviderEvidenceRepositoryPhase147Tests(
            methodName="runTest"
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        phase144_fixture = fixture.fixture
        self.root = phase144_fixture.root
        self.verification = phase144_fixture._verify()
        self.source_authentication = (
            phase144_fixture.service._authentications.get(
                phase144_fixture.authentication_receipt.report_authentication_id
            ).to_dict()["provider_report_authentication"]
        )
        self.source_dispatch = (
            phase144_fixture.fixture.fixture.fixture.dispatch
        )
        self.now = datetime(2026, 7, 30, 10, 8, 50, tzinfo=UTC)
        self.lifecycle = self._lifecycle()
        self.request = self._request(self.lifecycle)
        self.receipt = self._receipt(self.request)
        self.verified_policy, self.scope, self.assertion = self._identity(
            self.request,
            self.receipt,
            self.lifecycle,
        )

    def _lifecycle(self, **changes):
        mission = self.source_dispatch.to_dict()["mission"]
        values = {
            "policy_version": 1,
            "mission_id": mission["mission_id"],
            "mission_sha256": mission["mission_sha256"],
            "scope_reference_sha256": "sha256:"
            + hashlib.sha256(mission["scope_reference"].encode("utf-8")).hexdigest(),
            "retention_seconds": 2_592_000,
            "legal_hold_authority_role": "independent.legal-hold",
            "deletion_deadline_seconds": 86_400,
            "encryption_profile_id": "encryption.synthetic-kms-v1",
            "encryption_profile_sha256": "sha256:" + "93" * 32,
            "access_policy_id": "access.synthetic-mission-v1",
            "access_policy_sha256": "sha256:" + "94" * 32,
            "maximum_access_seconds": 300,
            "residency_policy_id": "residency.synthetic-us-v1",
            "residency_policy_sha256": "sha256:" + "95" * 32,
            "allowed_region_ids": ["region.synthetic-a", "region.synthetic-b"],
            "minimum_replica_count": 2,
            "created_at": "2026-07-30T10:08:39Z",
        }
        values.update(changes)
        return build_provider_evidence_lifecycle_policy(
            self.fixture.decision,
            **values,
        )

    def _request(self, lifecycle, **changes):
        policy = lifecycle.to_dict()
        values = {
            "retention_policy_id": lifecycle.policy_id,
            "retention_policy_sha256": lifecycle.policy_sha256,
            "residency_policy_id": policy["residency"]["policy_id"],
            "residency_policy_sha256": policy["residency"]["policy_sha256"],
            "encryption_profile_id": policy["encryption"]["profile_id"],
            "encryption_profile_sha256": policy["encryption"]["profile_sha256"],
            "access_policy_id": policy["access"]["policy_id"],
            "access_policy_sha256": policy["access"]["policy_sha256"],
            "requested_at": "2026-07-30T10:08:40Z",
            "expires_at": "2026-07-30T10:12:00Z",
        }
        values.update(changes)
        return build_provider_evidence_repository_ingest_request(
            self.fixture.decision,
            self.verification,
            **values,
        )

    def _receipt(self, request, **changes):
        values = {
            "adapter_id": "repository.contract-test",
            "adapter_version": "1.0.0",
            "adapter_build_sha256": "sha256:" + "85" * 32,
            "repository_id": "repository.synthetic-001",
            "object_version_id": "version.synthetic-001",
            "outcome": "accepted",
            "responded_at": "2026-07-30T10:08:45Z",
        }
        values.update(changes)
        return build_provider_evidence_repository_ingest_receipt(request, **values)

    def _identity(
        self,
        request,
        receipt,
        lifecycle,
        *,
        issued_at: str = "2026-07-30T10:08:46Z",
        scope_expires_at: str = "2026-07-30T10:11:40Z",
    ):
        operation = PrincipalOperation.EVIDENCE_REPOSITORY_ACKNOWLEDGE
        policy = self.root.factory.policy(
            max_assertion_lifetime_seconds=300,
            max_scope_lifetime_seconds=600,
            policy_version=POLICY_VERSION,
            store_id=self.root.store_id,
            allowed_profiles=[PROFILE_ID],
            allowed_subjects=[SUBJECT],
            allowed_operations=[operation.value],
        )
        verified_policy = verify_trust_policy(
            policy,
            {ROOT_KEY_ID: public_bytes(self.root.factory.root_private)},
            expected_audience=AUDIENCE,
            expected_store_id=self.root.store_id,
            expected_root_key_id=ROOT_KEY_ID,
            minimum_policy_version=7,
            clock=lambda: self.now,
        )
        mission = self.root.mission
        grant = self.root.factory.grant(
            grant_id=GRANT_ID,
            profile_id=PROFILE_ID,
            subject=SUBJECT,
            store_id=self.root.store_id,
            mission_id=mission.mission_id,
            mission_context_hash=self.root.stored.context_hash,
            scope_reference=mission.scope_reference,
            scope_document_hash=mission.scope_document_hash,
            environment=mission.environment.value,
            max_action_tier=mission.max_action_tier.value,
            constraints_hash=sha256_text(canonical_json(mission.to_dict()["constraints"])),
            operations=[operation.value],
            policy_version=POLICY_VERSION,
            issued_at="2026-07-30T10:08:40Z",
            not_before="2026-07-30T10:08:40Z",
            expires_at=scope_expires_at,
        )
        scope = self.root.factory.verify_grant(
            grant,
            verified_policy,
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
            expected_operation=operation,
            clock=lambda: self.now,
        )
        intent = {
            "ingest_receipt_selection_sha256": (
                provider_evidence_repository_ingest_receipt_selection_sha256(
                    receipt
                )
            ),
            "ingest_request_sha256": request.request_sha256,
            "lifecycle_policy_sha256": lifecycle.policy_sha256,
            "mission_id": mission.mission_id,
            "principal_profile_id": PROFILE_ID,
        }
        assertion = self.root.factory.assertion(
            grant=grant,
            assertion_id=ASSERTION_ID,
            policy_version=POLICY_VERSION,
            scope_grant_id=grant.grant_id,
            subject=SUBJECT,
            profile_id=PROFILE_ID,
            audience=AUDIENCE,
            store_id=self.root.store_id,
            mission_id=mission.mission_id,
            operation=operation,
            operation_intent_sha256=compute_operation_intent_hash(
                operation,
                intent,
            ),
            issued_at=issued_at,
            not_before=issued_at,
            expires_at="2026-07-30T10:10:00Z",
        )
        return verified_policy, scope, assertion

    def _authenticate(self, **changes):
        values = {
            "request": self.request,
            "receipt": self.receipt,
            "lifecycle_policy": self.lifecycle,
            "source_report_authentication": self.source_authentication,
            "source_dispatch": self.source_dispatch,
            "repository_assertion": self.assertion,
            "verified_policy": self.verified_policy,
            "repository_scope": self.scope,
            "repository_principal_subject": SUBJECT,
            "repository_principal_profile_id": PROFILE_ID,
            "expected_audience": AUDIENCE,
            "expected_store_id": self.root.store_id,
            "clock": lambda: self.now,
        }
        values.update(changes)
        return authenticate_provider_evidence_repository_ingest_receipt(**values)

    def test_authentication_binds_full_lineage_and_preserves_boundary(self) -> None:
        authenticated = self._authenticate()
        document = authenticated.to_dict()
        self.assertTrue(document["authentication_id"].startswith("ERI-"))
        self.assertEqual(
            document["repository_attestor"]["subject"],
            SUBJECT,
        )
        self.assertEqual(
            document["source_dispatch"]["mission"]["mission_id"],
            document["lifecycle_policy"]["mission"]["mission_id"],
        )
        self.assertEqual(
            document["authentication_status"],
            "authenticated_expected_repository_principal",
        )
        self.assertEqual(
            document["repository_control_status"],
            "provider_assertions_not_independently_verified",
        )
        self.assertEqual(document["runtime_effect"], "none")
        self.assertFalse(document["raw_evidence_in_contract"])

    def test_exact_receipt_selection_and_failure_outcome_authenticate_only_identity(self) -> None:
        changed_receipt = self._receipt(
            self.request,
            outcome="failed",
            object_version_id="version.synthetic-failed",
        )
        with self.assertRaises(PrincipalAuthenticationError):
            self._authenticate(receipt=changed_receipt)
        policy, scope, assertion = self._identity(
            self.request,
            changed_receipt,
            self.lifecycle,
        )
        document = self._authenticate(
            receipt=changed_receipt,
            verified_policy=policy,
            repository_scope=scope,
            repository_assertion=assertion,
        ).to_dict()
        self.assertEqual(document["ingest_receipt"]["outcome"], "failed")
        self.assertEqual(document["evidence_custody_status"], "provider_report_only")

    def test_lifecycle_references_and_decision_must_match_exactly(self) -> None:
        policy = self.lifecycle.to_dict()
        mismatches = (
            {"retention_policy_sha256": "sha256:" + "01" * 32},
            {"residency_policy_id": "residency.synthetic-wrong-v1"},
            {"encryption_profile_sha256": "sha256:" + "02" * 32},
            {"access_policy_id": "access.synthetic-wrong-v1"},
        )
        for changes in mismatches:
            with self.subTest(changes=changes):
                request = self._request(self.lifecycle, **changes)
                receipt = self._receipt(request)
                with self.assertRaisesRegex(
                    PrincipalAuthenticationError,
                    "lifecycle binding",
                ):
                    self._authenticate(request=request, receipt=receipt)
        changed_policy = copy.deepcopy(policy)
        changed_policy["custody_decision"]["record_sha256"] = "sha256:" + "03" * 32
        body = {
            key: value
            for key, value in changed_policy.items()
            if key not in {"policy_id", "policy_sha256"}
        }
        digest = _canonical_sha256(
            {"domain": "sunderkey.provider-evidence-lifecycle-policy.v1", "policy": body}
        )
        changed_policy["policy_id"] = (
            "ELP-" + digest.removeprefix("sha256:")[:32].upper()
        )
        changed_policy["policy_sha256"] = digest
        changed_lifecycle = ProviderEvidenceLifecyclePolicy.from_dict(changed_policy)
        request = self._request(changed_lifecycle)
        receipt = self._receipt(request)
        with self.assertRaisesRegex(PrincipalAuthenticationError, "custody decision"):
            self._authenticate(
                request=request,
                receipt=receipt,
                lifecycle_policy=changed_lifecycle,
            )

    def test_source_report_dispatch_and_mission_lineage_are_required(self) -> None:
        wrong_mission = self._lifecycle(mission_id="mission.synthetic-wrong")
        request = self._request(wrong_mission)
        receipt = self._receipt(request)
        with self.assertRaisesRegex(PrincipalAuthenticationError, "source mission"):
            self._authenticate(
                request=request,
                receipt=receipt,
                lifecycle_policy=wrong_mission,
            )
        changed_source = copy.deepcopy(self.source_authentication)
        changed_source["report_authentication_id"] = "EPA-" + "00" * 16
        with self.assertRaises(Exception):
            self._authenticate(source_report_authentication=changed_source)

    def test_expected_identity_and_time_order_fail_closed(self) -> None:
        with self.assertRaisesRegex(PrincipalAuthenticationError, "expected identity"):
            self._authenticate(repository_principal_subject="service:other")
        with self.assertRaisesRegex(PrincipalAuthenticationError, "ingest window"):
            self._authenticate(
                clock=lambda: datetime(2026, 7, 30, 10, 12, 1, tzinfo=UTC)
            )
        policy, scope, assertion = self._identity(
            self.request,
            self.receipt,
            self.lifecycle,
            issued_at="2026-07-30T10:08:44Z",
        )
        with self.assertRaisesRegex(PrincipalAuthenticationError, "precedes"):
            self._authenticate(
                verified_policy=policy,
                repository_scope=scope,
                repository_assertion=assertion,
            )

    def test_scope_cannot_exceed_lifecycle_access_duration(self) -> None:
        short_policy = self._lifecycle(maximum_access_seconds=60)
        request = self._request(short_policy)
        receipt = self._receipt(request)
        policy, scope, assertion = self._identity(request, receipt, short_policy)
        with self.assertRaisesRegex(PrincipalAuthenticationError, "access duration"):
            self._authenticate(
                request=request,
                receipt=receipt,
                lifecycle_policy=short_policy,
                verified_policy=policy,
                repository_scope=scope,
                repository_assertion=assertion,
            )

    def test_authenticated_wrapper_cannot_be_directly_forged(self) -> None:
        authenticated = self._authenticate()
        with self.assertRaisesRegex(TypeError, "only by"):
            AuthenticatedProviderEvidenceRepositoryIngestReceipt(
                authentication_id=authenticated.authentication_id,
                authentication_sha256=authenticated.authentication_sha256,
                ingest_request=authenticated.ingest_request,
                ingest_receipt=authenticated.ingest_receipt,
                lifecycle_policy=authenticated.lifecycle_policy,
                source_report_authentication=authenticated.source_report_authentication,
                source_dispatch=authenticated.source_dispatch,
                repository_attestor=authenticated.repository_attestor,
                authenticated_at=authenticated.authenticated_at,
                _proof=b"wrong",
            )

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is not installed")
    def test_authentication_matches_published_schema(self) -> None:
        def schema(name: str):
            return json.loads((SCHEMAS / name).read_text(encoding="utf-8"))

        acknowledgement_schema = schema(
            "collaboration-executor-acknowledgement-v1.schema.json"
        )
        acknowledgement_authentication_schema = schema(
            "collaboration-executor-acknowledgement-authentication-v1.schema.json"
        )
        acknowledgement_authentication_schema["properties"]["acknowledgement"] = (
            acknowledgement_schema
        )
        provider_report_schema = schema(
            "collaboration-executor-provider-report-v1.schema.json"
        )
        provider_report_schema["properties"]["provider_acknowledgement"] = (
            acknowledgement_schema
        )
        source_authentication_schema = schema(
            "collaboration-executor-provider-report-authentication-v1.schema.json"
        )
        source_authentication_schema["properties"]["provider_report"] = (
            provider_report_schema
        )
        source_authentication_schema["properties"]["acknowledgement_authentication"] = (
            acknowledgement_authentication_schema
        )
        request_schema = schema(
            "provider-evidence-repository-ingest-request-v1.schema.json"
        )
        request_schema["properties"]["evidence_verification"] = schema(
            "collaboration-executor-provider-evidence-verification-v1.schema.json"
        )
        authentication_schema = schema(
            "provider-evidence-repository-ingest-authentication-v1.schema.json"
        )
        authentication_schema["properties"]["ingest_request"] = request_schema
        authentication_schema["properties"]["ingest_receipt"] = schema(
            "provider-evidence-repository-ingest-receipt-v1.schema.json"
        )
        authentication_schema["properties"]["lifecycle_policy"] = schema(
            "provider-evidence-lifecycle-policy-v1.schema.json"
        )
        authentication_schema["properties"]["source_report_authentication"] = (
            source_authentication_schema
        )
        authentication_schema["properties"]["source_dispatch"] = schema(
            "collaboration-executor-dispatch-v1.schema.json"
        )
        Draft202012Validator.check_schema(authentication_schema)
        Draft202012Validator(authentication_schema).validate(
            self._authenticate().to_dict()
        )

    def test_contract_has_no_raw_evidence_or_runtime_implementation(self) -> None:
        serialized = json.dumps(self._authenticate().to_dict(), sort_keys=True)
        self.assertNotIn(phase147.phase144.EVIDENCE.decode("ascii"), serialized)
        self.assertNotIn("\u2014", serialized)
        source = (
            ROOT / "src/sunderkey/provider_evidence_repository_authentication.py"
        ).read_text(encoding="utf-8")
        imports = {
            alias.name.split(".")[0]
            for node in ast.walk(ast.parse(source))
            if isinstance(node, (ast.Import, ast.ImportFrom))
            for alias in node.names
        }
        self.assertFalse(
            imports
            & {
                "asyncio",
                "boto3",
                "google",
                "httpx",
                "requests",
                "socket",
                "sqlite3",
                "subprocess",
                "urllib",
            }
        )


if __name__ == "__main__":
    unittest.main()

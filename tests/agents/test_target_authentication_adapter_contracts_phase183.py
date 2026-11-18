from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path
from types import MappingProxyType

import sunderkey
from sunderkey.target_authentication_adapter_contracts import (
    AUTHENTICATION_MODE_PROFILES,
    NO_CLAIMS,
    NO_EFFECTS,
    AuthenticationFactor,
    AuthenticationFailureCode,
    AuthenticationMode,
    AuthenticationOperation,
    AuthenticationOutcome,
    AuthenticationProfileEvidence,
    AuthenticationProtocol,
    CredentialLeaseMode,
    ExecutionEnvironment,
    FlowStage,
    LifecycleObligation,
    PrincipalTopology,
    SessionCarrier,
    TargetAuthenticationCommand,
    TargetAuthenticationContractError,
    TargetAuthenticationFlowEvidence,
    TargetAuthenticationPolicy,
    TargetAuthenticationProviderBinding,
    TargetAuthenticationReceipt,
    TargetAuthenticationResult,
    TargetCredentialProvenance,
    V1TargetSessionEvidenceBinding,
    canonical_json,
    issue_target_authentication_receipt,
    parse_target_authentication_command,
    parse_target_authentication_flow_evidence,
    parse_target_authentication_policy,
    parse_target_authentication_provider_binding,
    parse_target_authentication_receipt,
    parse_target_authentication_record,
    parse_target_authentication_result,
    parse_target_credential_provenance,
    transport_credential_reference_sha256,
    verify_target_authentication_chain,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "registry/schemas/target-authentication-adapter-contract-v2.schema.json"


def _digest(character: str) -> str:
    return "sha256:" + character * 64


def _v1(suffix: str = "ONE") -> V1TargetSessionEvidenceBinding:
    marker = {"ONE": "A", "TWO": "B", "FACTORS": "C"}.get(suffix, "D")
    return V1TargetSessionEvidenceBinding(
        execution_policy_id="ECP-" + marker * 32,
        execution_policy_sha256=_digest("1"),
        intent_sha256=_digest("2"),
        execution_request_id="ECRQ-" + marker * 32,
        execution_request_sha256=_digest("3"),
        admission_receipt_id="ECAR-" + marker * 32,
        admission_receipt_sha256=_digest("4"),
        runtime_policy_id="ATSP-" + marker * 32,
        runtime_policy_sha256=_digest("5"),
        runtime_receipt_id="ASR-" + marker * 32,
        runtime_receipt_sha256=_digest("6"),
    )


def _provenance(
    provider: TargetAuthenticationProviderBinding,
    principal: str = "alice",
    *,
    lease_mode: CredentialLeaseMode = CredentialLeaseMode.ONE_TIME,
    marker: str = "a",
    factor: AuthenticationFactor = AuthenticationFactor.PASSWORD_REFERENCE,
) -> TargetCredentialProvenance:
    return TargetCredentialProvenance(
        provider_binding=provider.content_binding,
        principal_ref=f"principalref:{principal}",
        factor=factor,
        descriptor_id="CBD-" + marker.upper() * 32,
        descriptor_sha256=_digest(marker),
        lease_id="CLZ-" + marker.upper() * 32,
        lease_sha256=_digest("b"),
        lease_mode=lease_mode,
        lease_issued_at="2026-09-20T10:00:00Z",
        lease_expires_at="2026-09-20T11:00:00Z",
        lease_use_number=1,
        source_credential_ref=f"credentialref:vault/{principal}",
        transport_credential_ref_sha256=transport_credential_reference_sha256(
            f"credref:vault/{principal}"
        ),
        mapping_attestation_sha256=_digest("c"),
        created_at="2026-09-20T10:01:00Z",
    )


def _command_from(
    source: TargetAuthenticationCommand, **changes: object
) -> TargetAuthenticationCommand:
    values: dict[str, object] = {
        "policy_binding": source.policy_binding,
        "provider_binding": source.provider_binding,
        "execution_environment": source.execution_environment,
        "operation": source.operation,
        "mode": source.mode,
        "profile_evidence": source.profile_evidence,
        "v1_evidence": source.v1_evidence,
        "credential_provenance": source.credential_provenance,
        "lifecycle_obligations": source.lifecycle_obligations,
        "requested_session_ref": source.requested_session_ref,
        "predecessor_session_ref": source.predecessor_session_ref,
        "fixture_scenario_ref": source.fixture_scenario_ref,
        "issued_at": source.issued_at,
        "expires_at": source.expires_at,
    }
    values.update(changes)
    return TargetAuthenticationCommand(**values)


def _result_from(
    source: TargetAuthenticationResult, **changes: object
) -> TargetAuthenticationResult:
    values: dict[str, object] = {
        "command_binding": source.command_binding,
        "provider_binding": source.provider_binding,
        "execution_environment": source.execution_environment,
        "outcome": source.outcome,
        "failure_code": source.failure_code,
        "flow_evidence": source.flow_evidence,
        "resulting_session_ref": source.resulting_session_ref,
        "session_evidence_sha256": source.session_evidence_sha256,
        "provider_attestation_sha256": source.provider_attestation_sha256,
        "environment_attestation_sha256": source.environment_attestation_sha256,
        "satisfied_lifecycle_obligations": source.satisfied_lifecycle_obligations,
        "pending_lifecycle_obligations": source.pending_lifecycle_obligations,
        "completed_at": source.completed_at,
    }
    values.update(changes)
    return TargetAuthenticationResult(**values)


def _chain(
    *,
    external: bool = False,
    mode: AuthenticationMode = AuthenticationMode.FORM_LOGIN_PASSWORD,
    topology: PrincipalTopology = PrincipalTopology.SINGLE_PRINCIPAL,
    operation: AuthenticationOperation = AuthenticationOperation.ACQUIRE_SESSION,
    provider_expires_at: str = "2026-09-20T11:00:00Z",
    supported_operations: tuple[AuthenticationOperation, ...] = (
        AuthenticationOperation.ACQUIRE_SESSION,
        AuthenticationOperation.REFRESH_SESSION,
        AuthenticationOperation.TERMINATE_SESSION,
    ),
) -> dict[str, object]:
    environment = (
        ExecutionEnvironment.EXTERNAL_RUNTIME_OBSERVATION
        if external
        else ExecutionEnvironment.DETERMINISTIC_FIXTURE
    )
    profile = AuthenticationProfileEvidence.for_mode(mode, topology)
    provider = TargetAuthenticationProviderBinding(
        provider_ref="providerref:test",
        instance_ref="instanceref:test/one",
        implementation_name="fixture.auth" if not external else "runtime.auth",
        implementation_version="1.0.0",
        execution_environment=environment,
        artifact_sha256=_digest("7"),
        configuration_sha256=_digest("8"),
        environment_attestation_sha256=_digest("9"),
        supported_profiles=(profile,),
        supported_operations=supported_operations,
        issued_at="2026-09-20T10:00:00Z",
        expires_at=provider_expires_at,
    )
    principals = ("alice", "bob") if topology is PrincipalTopology.MULTI_PRINCIPAL else ("alice",)
    markers = iter("abcdef0123456789")
    lease_mode = (
        CredentialLeaseMode.SESSION_BOUND
        if operation is AuthenticationOperation.REFRESH_SESSION
        else CredentialLeaseMode.ONE_TIME
    )
    provenance = [
        _provenance(
            provider,
            principal,
            marker=next(markers),
            factor=factor,
            lease_mode=lease_mode,
        )
        for principal in principals
        for factor in profile.factors
    ]
    policy = TargetAuthenticationPolicy(
        tenant_ref="tenantref:test",
        mission_ref="missionref:test",
        scope_ref="scoperef:test",
        target_ref="targetref:test",
        provider_binding=provider.content_binding,
        mode=profile.mode,
        profile_evidence=profile,
        v1_evidence=_v1(),
        credential_provenance=tuple(item.content_binding for item in provenance),
        lifecycle_obligations=profile.lifecycle_obligations,
        maximum_attempts=1,
        issued_at="2026-09-20T10:00:00Z",
        expires_at="2026-09-20T11:00:00Z",
    )
    command_obligations = tuple(profile.lifecycle_obligations)
    if operation is AuthenticationOperation.REFRESH_SESSION:
        command_obligations += (LifecycleObligation.REFRESH_PREDECESSOR_BOUND,)
    command = TargetAuthenticationCommand(
        policy_binding=policy.content_binding,
        provider_binding=provider.content_binding,
        execution_environment=environment,
        operation=operation,
        mode=profile.mode,
        profile_evidence=profile,
        v1_evidence=policy.v1_evidence,
        credential_provenance=policy.credential_provenance,
        lifecycle_obligations=command_obligations,
        requested_session_ref="sessionref:test/new",
        predecessor_session_ref=(
            "sessionref:test/old" if operation is AuthenticationOperation.REFRESH_SESSION else None
        ),
        fixture_scenario_ref=None if external else "fixtureref:test/login",
        issued_at="2026-09-20T10:02:00Z",
        expires_at="2026-09-20T10:10:00Z",
    )
    provider_attestation = _digest("e") if external else None
    environment_attestation = _digest("9") if external else None
    evidence = tuple(
        TargetAuthenticationFlowEvidence(
            command_binding=command.content_binding,
            provider_binding=provider.content_binding,
            execution_environment=environment,
            stage=stage,
            sequence=index,
            input_evidence_sha256=_digest(str(index)),
            output_evidence_sha256=None if index == 1 else _digest(str(index + 1)),
            provider_attestation_sha256=provider_attestation,
            environment_attestation_sha256=environment_attestation,
            failure_code=None,
            observed_at=f"2026-09-20T10:0{index + 2}:00Z",
        )
        for index, stage in enumerate(profile.successful_flow_stages, start=1)
    )
    completed_minute = len(evidence) + 3
    result = TargetAuthenticationResult(
        command_binding=command.content_binding,
        provider_binding=provider.content_binding,
        execution_environment=environment,
        outcome=AuthenticationOutcome.AUTHENTICATED,
        failure_code=None,
        flow_evidence=tuple(item.content_binding for item in evidence),
        resulting_session_ref="sessionref:test/new",
        session_evidence_sha256=_digest("4"),
        provider_attestation_sha256=provider_attestation,
        environment_attestation_sha256=environment_attestation,
        satisfied_lifecycle_obligations=tuple(
            obligation
            for obligation in command_obligations
            if obligation
            not in {
                LifecycleObligation.LOGOUT_REQUIRED,
                LifecycleObligation.REVOCATION_OBSERVATION_REQUIRED,
            }
        ),
        pending_lifecycle_obligations=(
            LifecycleObligation.LOGOUT_REQUIRED,
            LifecycleObligation.REVOCATION_OBSERVATION_REQUIRED,
        ),
        completed_at=f"2026-09-20T10:0{completed_minute}:00Z",
    )
    receipt = issue_target_authentication_receipt(
        provider,
        provenance,
        policy,
        command,
        evidence,
        result,
        issued_at=f"2026-09-20T10:0{completed_minute + 1}:00Z",
    )
    return {
        "profile": profile,
        "provider": provider,
        "provenance": tuple(provenance),
        "policy": policy,
        "command": command,
        "evidence": evidence,
        "result": result,
        "receipt": receipt,
    }


class TargetAuthenticationAdapterContractsPhase183Tests(unittest.TestCase):
    def test_deterministic_fixture_chain_is_content_addressed_and_verifies(self) -> None:
        chain = _chain()
        verify_target_authentication_chain(
            chain["provider"],
            chain["provenance"],
            chain["policy"],
            chain["command"],
            chain["evidence"],
            chain["result"],
            chain["receipt"],
        )
        self.assertTrue(chain["provider"].binding_id.startswith("TAPB-"))
        self.assertTrue(chain["provenance"][0].provenance_id.startswith("TACP-"))
        self.assertTrue(chain["profile"].profile_id.startswith("TAPE-"))
        self.assertTrue(chain["policy"].policy_id.startswith("TAAP-"))
        self.assertTrue(chain["command"].command_id.startswith("TAAC-"))
        self.assertTrue(chain["evidence"][0].evidence_id.startswith("TAFE-"))
        self.assertTrue(chain["result"].result_id.startswith("TAAR-"))
        self.assertTrue(chain["receipt"].receipt_id.startswith("TAAT-"))
        self.assertFalse(chain["receipt"].lifecycle_complete)

    def test_external_chain_requires_and_verifies_distinct_attestations(self) -> None:
        chain = _chain(external=True)
        verify_target_authentication_chain(
            chain["provider"],
            chain["provenance"],
            chain["policy"],
            chain["command"],
            chain["evidence"],
            chain["result"],
            chain["receipt"],
        )
        self.assertIsNone(chain["command"].fixture_scenario_ref)
        self.assertEqual(
            chain["result"].environment_attestation_sha256,
            chain["provider"].environment_attestation_sha256,
        )
        self.assertNotEqual(
            chain["result"].provider_attestation_sha256,
            chain["result"].environment_attestation_sha256,
        )

    def test_all_seven_parsers_and_generic_parser_round_trip_canonical_json(self) -> None:
        chain = _chain()
        records_and_parsers = (
            (chain["provider"], parse_target_authentication_provider_binding),
            (chain["provenance"][0], parse_target_credential_provenance),
            (chain["policy"], parse_target_authentication_policy),
            (chain["command"], parse_target_authentication_command),
            (chain["evidence"][0], parse_target_authentication_flow_evidence),
            (chain["result"], parse_target_authentication_result),
            (chain["receipt"], parse_target_authentication_receipt),
        )
        for record, parser in records_and_parsers:
            document = canonical_json(record.to_dict())
            self.assertEqual(canonical_json(parser(document).to_dict()), document)
            self.assertEqual(
                canonical_json(parse_target_authentication_record(document).to_dict()), document
            )

    def test_schema_accepts_every_record_and_rejects_unknown_fields(self) -> None:
        try:
            from jsonschema import Draft202012Validator
        except ImportError:
            self.skipTest("jsonschema is not installed")
        validator = Draft202012Validator(json.loads(SCHEMA.read_text(encoding="utf-8")))
        chain = _chain(external=True)
        records = (
            chain["provider"],
            chain["provenance"][0],
            chain["policy"],
            chain["command"],
            chain["evidence"][0],
            chain["result"],
            chain["receipt"],
        )
        for record in records:
            validator.validate(record.to_dict())
        altered = copy.deepcopy(chain["policy"].to_dict())
        altered["unexpected"] = True
        self.assertTrue(list(validator.iter_errors(altered)))

    def test_profile_matrix_is_immutable_exact_and_topology_specific(self) -> None:
        self.assertIsInstance(AUTHENTICATION_MODE_PROFILES, MappingProxyType)
        with self.assertRaises(TypeError):
            AUTHENTICATION_MODE_PROFILES[
                (AuthenticationMode.BASIC_REFERENCE, PrincipalTopology.MULTI_PRINCIPAL)
            ] = next(iter(AUTHENTICATION_MODE_PROFILES.values()))
        with self.assertRaisesRegex(TargetAuthenticationContractError, "unsupported"):
            AuthenticationProfileEvidence.for_mode(
                AuthenticationMode.BASIC_REFERENCE, PrincipalTopology.FEDERATED_PRINCIPAL
            )
        valid = AuthenticationProfileEvidence.for_mode(
            AuthenticationMode.OAUTH2_PKCE, PrincipalTopology.FEDERATED_PRINCIPAL
        )
        with self.assertRaisesRegex(TargetAuthenticationContractError, "immutable profile"):
            AuthenticationProfileEvidence(
                mode=valid.mode,
                protocol=valid.protocol,
                factors=valid.factors,
                carrier=SessionCarrier.AUTHORIZATION_HEADER_REFERENCE,
                topology=valid.topology,
                successful_flow_stages=valid.successful_flow_stages,
                lifecycle_obligations=valid.lifecycle_obligations,
            )
        self.assertIn(
            (AuthenticationMode.BASIC_REFERENCE, PrincipalTopology.MULTI_PRINCIPAL),
            AUTHENTICATION_MODE_PROFILES,
        )

    def test_email_otp_profiles_are_explicit_for_single_and_multi_principal(self) -> None:
        for topology in (
            PrincipalTopology.SINGLE_PRINCIPAL,
            PrincipalTopology.MULTI_PRINCIPAL,
        ):
            profile = AuthenticationProfileEvidence.for_mode(
                AuthenticationMode.FORM_LOGIN_EMAIL_OTP, topology
            )
            self.assertEqual(profile.protocol, AuthenticationProtocol.HTML_FORM)
            self.assertEqual(profile.carrier, SessionCarrier.BROWSER_COOKIE_JAR_REFERENCE)
            self.assertEqual(
                set(profile.factors),
                {
                    AuthenticationFactor.PASSWORD_REFERENCE,
                    AuthenticationFactor.EMAIL_OTP_REFERENCE,
                },
            )
            self.assertIn(FlowStage.CHALLENGE_OBSERVED, profile.successful_flow_stages)
            self.assertIn(LifecycleObligation.MFA_OPERATOR_BOUND, profile.lifecycle_obligations)

    def test_profile_serializes_protocol_factors_carrier_and_topology(self) -> None:
        profile = AuthenticationProfileEvidence.for_mode(
            AuthenticationMode.FORM_LOGIN_TOTP, PrincipalTopology.SINGLE_PRINCIPAL
        )
        document = profile.to_dict()
        self.assertEqual(document["protocol"], AuthenticationProtocol.HTML_FORM.value)
        self.assertEqual(
            document["factors"],
            [
                AuthenticationFactor.PASSWORD_REFERENCE.value,
                AuthenticationFactor.TOTP_REFERENCE.value,
            ],
        )
        self.assertEqual(document["carrier"], SessionCarrier.BROWSER_COOKIE_JAR_REFERENCE)
        self.assertEqual(document["topology"], PrincipalTopology.SINGLE_PRINCIPAL)

    def test_credential_provenance_redacts_transport_reference_and_preserves_digest(self) -> None:
        chain = _chain()
        record = chain["provenance"][0]
        serialized = canonical_json(record.to_dict())
        self.assertIn("credentialref:vault/alice", serialized)
        self.assertNotIn("credref:vault/alice", serialized)
        self.assertEqual(
            record.transport_credential_ref_sha256,
            transport_credential_reference_sha256("credref:vault/alice"),
        )
        with self.assertRaisesRegex(TargetAuthenticationContractError, "credref namespace"):
            transport_credential_reference_sha256("credentialref:vault/alice")

    def test_credential_lease_and_creation_window_invariants(self) -> None:
        provider = _chain()["provider"]
        with self.assertRaisesRegex(TargetAuthenticationContractError, "one-time lease"):
            TargetCredentialProvenance(
                provider.content_binding,
                "principalref:alice",
                AuthenticationFactor.PASSWORD_REFERENCE,
                "CBD-" + "A" * 32,
                _digest("1"),
                "CLZ-" + "B" * 32,
                _digest("2"),
                CredentialLeaseMode.ONE_TIME,
                "2026-09-20T10:00:00Z",
                "2026-09-20T11:00:00Z",
                2,
                "credentialref:vault/alice",
                _digest("3"),
                _digest("4"),
                "2026-09-20T10:01:00Z",
            )
        with self.assertRaisesRegex(TargetAuthenticationContractError, "inside the lease window"):
            TargetCredentialProvenance(
                provider.content_binding,
                "principalref:alice",
                AuthenticationFactor.PASSWORD_REFERENCE,
                "CBD-" + "A" * 32,
                _digest("1"),
                "CLZ-" + "B" * 32,
                _digest("2"),
                CredentialLeaseMode.SESSION_BOUND,
                "2026-09-20T10:00:00Z",
                "2026-09-20T11:00:00Z",
                2,
                "credentialref:vault/alice",
                _digest("3"),
                _digest("4"),
                "2026-09-20T11:00:00Z",
            )

    def test_external_attestation_presence_and_distinctness_fail_closed(self) -> None:
        chain = _chain(external=True)
        evidence = chain["evidence"][0]
        with self.assertRaisesRegex(TargetAuthenticationContractError, "requires provider"):
            TargetAuthenticationFlowEvidence(
                evidence.command_binding,
                evidence.provider_binding,
                evidence.execution_environment,
                evidence.stage,
                evidence.sequence,
                evidence.input_evidence_sha256,
                evidence.output_evidence_sha256,
                None,
                None,
                evidence.failure_code,
                evidence.observed_at,
            )
        with self.assertRaisesRegex(TargetAuthenticationContractError, "must be distinct"):
            TargetAuthenticationFlowEvidence(
                evidence.command_binding,
                evidence.provider_binding,
                evidence.execution_environment,
                evidence.stage,
                evidence.sequence,
                evidence.input_evidence_sha256,
                evidence.output_evidence_sha256,
                _digest("9"),
                _digest("9"),
                evidence.failure_code,
                evidence.observed_at,
            )

    def test_fixture_rejects_runtime_attestations_and_missing_fixture_reference(self) -> None:
        chain = _chain()
        evidence = chain["evidence"][0]
        with self.assertRaisesRegex(TargetAuthenticationContractError, "fixture flow"):
            TargetAuthenticationFlowEvidence(
                evidence.command_binding,
                evidence.provider_binding,
                evidence.execution_environment,
                evidence.stage,
                evidence.sequence,
                evidence.input_evidence_sha256,
                evidence.output_evidence_sha256,
                _digest("1"),
                _digest("2"),
                evidence.failure_code,
                evidence.observed_at,
            )
        with self.assertRaisesRegex(TargetAuthenticationContractError, "fixture execution"):
            _command_from(chain["command"], fixture_scenario_ref=None)

    def test_provider_and_environment_attestation_mismatches_fail_verifier(self) -> None:
        chain = _chain(external=True)
        result = _result_from(
            chain["result"],
            provider_attestation_sha256=_digest("f"),
        )
        with self.assertRaisesRegex(TargetAuthenticationContractError, "terminal provider"):
            verify_target_authentication_chain(
                chain["provider"],
                chain["provenance"],
                chain["policy"],
                chain["command"],
                chain["evidence"],
                result,
            )
        result = _result_from(
            chain["result"],
            environment_attestation_sha256=_digest("a"),
        )
        with self.assertRaisesRegex(TargetAuthenticationContractError, "environment attestation"):
            verify_target_authentication_chain(
                chain["provider"],
                chain["provenance"],
                chain["policy"],
                chain["command"],
                chain["evidence"],
                result,
            )

    def test_provider_window_and_supported_operation_are_enforced(self) -> None:
        with self.assertRaisesRegex(TargetAuthenticationContractError, "times"):
            _chain(provider_expires_at="2026-09-20T10:30:00Z")
        with self.assertRaisesRegex(TargetAuthenticationContractError, "command operation"):
            _chain(supported_operations=(AuthenticationOperation.TERMINATE_SESSION,))

        chain = _chain()
        late_receipt = TargetAuthenticationReceipt(
            provider_binding=chain["provider"].content_binding,
            policy_binding=chain["policy"].content_binding,
            command_binding=chain["command"].content_binding,
            result_binding=chain["result"].content_binding,
            flow_evidence=tuple(item.content_binding for item in chain["evidence"]),
            execution_environment=ExecutionEnvironment.DETERMINISTIC_FIXTURE,
            lifecycle_complete=False,
            issued_at="2026-09-20T11:00:01Z",
        )
        with self.assertRaisesRegex(TargetAuthenticationContractError, "receipt chain"):
            verify_target_authentication_chain(
                chain["provider"],
                chain["provenance"],
                chain["policy"],
                chain["command"],
                chain["evidence"],
                chain["result"],
                late_receipt,
            )

    def test_upstream_and_credential_record_id_types_are_exact(self) -> None:
        raw_v1 = _v1().to_dict()
        raw_v1["execution_policy_id"] = "ATSP-" + "A" * 32
        with self.assertRaisesRegex(TargetAuthenticationContractError, "wrong record type"):
            V1TargetSessionEvidenceBinding.from_dict(raw_v1)

        provenance = _chain()["provenance"][0].to_dict()
        provenance["descriptor_id"] = "TAAP-" + "A" * 32
        with self.assertRaisesRegex(TargetAuthenticationContractError, "CBD record"):
            parse_target_credential_provenance(canonical_json(provenance))
        provenance = _chain()["provenance"][0].to_dict()
        provenance["lease_id"] = "TACP-" + "B" * 32
        with self.assertRaisesRegex(TargetAuthenticationContractError, "CLZ record"):
            parse_target_credential_provenance(canonical_json(provenance))

    def test_v1_evidence_rebinding_fails_before_execution_evidence(self) -> None:
        chain = _chain()
        command = _command_from(chain["command"], v1_evidence=_v1("TWO"))
        with self.assertRaisesRegex(TargetAuthenticationContractError, "v1 target session"):
            verify_target_authentication_chain(
                chain["provider"],
                chain["provenance"],
                chain["policy"],
                command,
                chain["evidence"],
                chain["result"],
            )

    def test_cross_provider_and_policy_swaps_fail_closed(self) -> None:
        first = _chain()
        second = _chain(external=True)
        with self.assertRaisesRegex(TargetAuthenticationContractError, "provider identity"):
            verify_target_authentication_chain(
                second["provider"],
                first["provenance"],
                first["policy"],
                first["command"],
                first["evidence"],
                first["result"],
            )
        command = _command_from(first["command"], policy_binding=second["policy"].content_binding)
        with self.assertRaisesRegex(TargetAuthenticationContractError, "policy binding"):
            verify_target_authentication_chain(
                first["provider"],
                first["provenance"],
                first["policy"],
                command,
                first["evidence"],
                first["result"],
            )

    def test_multi_principal_requires_distinct_principals(self) -> None:
        chain = _chain(topology=PrincipalTopology.MULTI_PRINCIPAL)
        verify_target_authentication_chain(
            chain["provider"],
            chain["provenance"],
            chain["policy"],
            chain["command"],
            chain["evidence"],
            chain["result"],
        )
        with self.assertRaisesRegex(TargetAuthenticationContractError, "provenance mismatch"):
            verify_target_authentication_chain(
                chain["provider"],
                (chain["provenance"][0], chain["provenance"][0]),
                chain["policy"],
                chain["command"],
                chain["evidence"],
                chain["result"],
            )

    def test_factor_coverage_rejects_missing_duplicate_and_wrong_factors(self) -> None:
        def context(
            profile: AuthenticationProfileEvidence,
            factors: tuple[AuthenticationFactor, ...],
        ) -> tuple[
            TargetAuthenticationProviderBinding,
            tuple[TargetCredentialProvenance, ...],
            TargetAuthenticationPolicy,
            TargetAuthenticationCommand,
            TargetAuthenticationResult,
        ]:
            provider = TargetAuthenticationProviderBinding(
                "providerref:factors",
                "instanceref:factors/one",
                "fixture.factors",
                "1.0.0",
                ExecutionEnvironment.DETERMINISTIC_FIXTURE,
                _digest("1"),
                _digest("2"),
                _digest("3"),
                (profile,),
                (
                    AuthenticationOperation.ACQUIRE_SESSION,
                    AuthenticationOperation.REFRESH_SESSION,
                    AuthenticationOperation.TERMINATE_SESSION,
                ),
                "2026-09-20T10:00:00Z",
                "2026-09-20T11:00:00Z",
            )
            provenance = tuple(
                _provenance(provider, marker=marker, factor=factor)
                for marker, factor in zip("abcdef"[: len(factors)], factors, strict=True)
            )
            policy = TargetAuthenticationPolicy(
                "tenantref:test",
                "missionref:test",
                "scoperef:test",
                "targetref:test",
                provider.content_binding,
                profile.mode,
                profile,
                _v1("FACTORS"),
                tuple(item.content_binding for item in provenance),
                profile.lifecycle_obligations,
                1,
                "2026-09-20T10:00:00Z",
                "2026-09-20T11:00:00Z",
            )
            command = TargetAuthenticationCommand(
                policy.content_binding,
                provider.content_binding,
                ExecutionEnvironment.DETERMINISTIC_FIXTURE,
                AuthenticationOperation.ACQUIRE_SESSION,
                profile.mode,
                profile,
                policy.v1_evidence,
                policy.credential_provenance,
                profile.lifecycle_obligations,
                "sessionref:test/new",
                None,
                "fixtureref:test/factors",
                "2026-09-20T10:02:00Z",
                "2026-09-20T10:10:00Z",
            )
            result = TargetAuthenticationResult(
                command.content_binding,
                provider.content_binding,
                ExecutionEnvironment.DETERMINISTIC_FIXTURE,
                AuthenticationOutcome.AUTHENTICATED,
                None,
                (),
                "sessionref:test/new",
                _digest("4"),
                None,
                None,
                (),
                profile.lifecycle_obligations,
                "2026-09-20T10:05:00Z",
            )
            return provider, provenance, policy, command, result

        email = AuthenticationProfileEvidence.for_mode(
            AuthenticationMode.FORM_LOGIN_EMAIL_OTP, PrincipalTopology.SINGLE_PRINCIPAL
        )
        with self.assertRaisesRegex(TargetAuthenticationContractError, "provenance count"):
            context(email, (AuthenticationFactor.PASSWORD_REFERENCE,))

        password = AuthenticationProfileEvidence.for_mode(
            AuthenticationMode.FORM_LOGIN_PASSWORD, PrincipalTopology.SINGLE_PRINCIPAL
        )
        duplicate = context(
            email,
            (
                AuthenticationFactor.PASSWORD_REFERENCE,
                AuthenticationFactor.PASSWORD_REFERENCE,
            ),
        )
        with self.assertRaisesRegex(
            TargetAuthenticationContractError, "duplicate principal factor"
        ):
            verify_target_authentication_chain(*duplicate[:4], (), duplicate[4])

        wrong = context(password, (AuthenticationFactor.BEARER_REFERENCE,))
        with self.assertRaisesRegex(TargetAuthenticationContractError, "factor coverage"):
            verify_target_authentication_chain(*wrong[:4], (), wrong[4])

        oauth = AuthenticationProfileEvidence.for_mode(
            AuthenticationMode.OAUTH2_PKCE, PrincipalTopology.FEDERATED_PRINCIPAL
        )
        with self.assertRaisesRegex(TargetAuthenticationContractError, "provenance count"):
            context(oauth, (AuthenticationFactor.PKCE_VERIFIER_REFERENCE,))
        wrong_federated = context(
            oauth,
            (
                AuthenticationFactor.PKCE_VERIFIER_REFERENCE,
                AuthenticationFactor.PASSWORD_REFERENCE,
            ),
        )
        with self.assertRaisesRegex(TargetAuthenticationContractError, "factor coverage"):
            verify_target_authentication_chain(*wrong_federated[:4], (), wrong_federated[4])

        with self.assertRaisesRegex(TargetAuthenticationContractError, "provenance count"):
            context(
                AuthenticationProfileEvidence.for_mode(
                    AuthenticationMode.FORM_LOGIN_EMAIL_OTP,
                    PrincipalTopology.MULTI_PRINCIPAL,
                ),
                (
                    AuthenticationFactor.PASSWORD_REFERENCE,
                    AuthenticationFactor.EMAIL_OTP_REFERENCE,
                ),
            )

    def test_policy_and_command_enforce_profile_factor_cardinality(self) -> None:
        chain = _chain()
        email = AuthenticationProfileEvidence.for_mode(
            AuthenticationMode.FORM_LOGIN_EMAIL_OTP, PrincipalTopology.SINGLE_PRINCIPAL
        )
        with self.assertRaisesRegex(TargetAuthenticationContractError, "provenance count"):
            TargetAuthenticationPolicy(
                "tenantref:test",
                "missionref:test",
                "scoperef:test",
                "targetref:test",
                chain["provider"].content_binding,
                email.mode,
                email,
                _v1(),
                (chain["provenance"][0].content_binding,),
                email.lifecycle_obligations,
                1,
                "2026-09-20T10:00:00Z",
                "2026-09-20T11:00:00Z",
            )
        extra = _provenance(chain["provider"], marker="d")
        with self.assertRaisesRegex(TargetAuthenticationContractError, "provenance count"):
            _command_from(
                chain["command"],
                credential_provenance=(
                    chain["provenance"][0].content_binding,
                    extra.content_binding,
                ),
            )

    def test_lifecycle_partition_and_active_session_requirements_fail_closed(self) -> None:
        chain = _chain()
        incomplete = _result_from(
            chain["result"],
            pending_lifecycle_obligations=(LifecycleObligation.LOGOUT_REQUIRED,),
        )
        with self.assertRaisesRegex(TargetAuthenticationContractError, "partition"):
            verify_target_authentication_chain(
                chain["provider"],
                chain["provenance"],
                chain["policy"],
                chain["command"],
                chain["evidence"],
                incomplete,
            )
        missing_termination = _result_from(
            chain["result"],
            satisfied_lifecycle_obligations=(
                LifecycleObligation.SECRET_NON_PERSISTENCE,
                LifecycleObligation.SESSION_ISOLATION,
                LifecycleObligation.REVOCATION_OBSERVATION_REQUIRED,
            ),
            pending_lifecycle_obligations=(LifecycleObligation.LOGOUT_REQUIRED,),
        )
        with self.assertRaisesRegex(TargetAuthenticationContractError, "lifecycle states"):
            verify_target_authentication_chain(
                chain["provider"],
                chain["provenance"],
                chain["policy"],
                chain["command"],
                chain["evidence"],
                missing_termination,
            )

        for unresolved in (
            LifecycleObligation.SECRET_NON_PERSISTENCE,
            LifecycleObligation.SESSION_ISOLATION,
        ):
            pending = (
                LifecycleObligation.LOGOUT_REQUIRED,
                LifecycleObligation.REVOCATION_OBSERVATION_REQUIRED,
                unresolved,
            )
            satisfied = tuple(
                item for item in chain["command"].lifecycle_obligations if item not in pending
            )
            result = _result_from(
                chain["result"],
                satisfied_lifecycle_obligations=satisfied,
                pending_lifecycle_obligations=pending,
            )
            with self.assertRaisesRegex(TargetAuthenticationContractError, "lifecycle states"):
                verify_target_authentication_chain(
                    chain["provider"],
                    chain["provenance"],
                    chain["policy"],
                    chain["command"],
                    chain["evidence"],
                    result,
                )

        for specialized, obligation in (
            (
                _chain(mode=AuthenticationMode.FORM_LOGIN_EMAIL_OTP),
                LifecycleObligation.MFA_OPERATOR_BOUND,
            ),
            (
                _chain(operation=AuthenticationOperation.REFRESH_SESSION),
                LifecycleObligation.REFRESH_PREDECESSOR_BOUND,
            ),
        ):
            pending = tuple(specialized["result"].pending_lifecycle_obligations) + (obligation,)
            satisfied = tuple(
                item
                for item in specialized["result"].satisfied_lifecycle_obligations
                if item is not obligation
            )
            result = _result_from(
                specialized["result"],
                satisfied_lifecycle_obligations=satisfied,
                pending_lifecycle_obligations=pending,
            )
            with self.assertRaisesRegex(TargetAuthenticationContractError, "lifecycle states"):
                verify_target_authentication_chain(
                    specialized["provider"],
                    specialized["provenance"],
                    specialized["policy"],
                    specialized["command"],
                    specialized["evidence"],
                    result,
                )

    def test_command_operation_and_session_reference_invariants(self) -> None:
        chain = _chain()
        with self.assertRaisesRegex(TargetAuthenticationContractError, "acquire command"):
            _command_from(chain["command"], predecessor_session_ref="sessionref:test/old")
        with self.assertRaisesRegex(TargetAuthenticationContractError, "refresh command"):
            _command_from(
                chain["command"],
                operation=AuthenticationOperation.REFRESH_SESSION,
                predecessor_session_ref="sessionref:test/new",
            )
        with self.assertRaisesRegex(TargetAuthenticationContractError, "terminate command"):
            _command_from(
                chain["command"],
                operation=AuthenticationOperation.TERMINATE_SESSION,
                predecessor_session_ref="sessionref:test/old",
            )

    def test_refresh_requires_session_bound_lease_and_predecessor_obligation(self) -> None:
        chain = _chain()
        obligations = tuple(chain["profile"].lifecycle_obligations) + (
            LifecycleObligation.REFRESH_PREDECESSOR_BOUND,
        )
        command = _command_from(
            chain["command"],
            operation=AuthenticationOperation.REFRESH_SESSION,
            predecessor_session_ref="sessionref:test/old",
            lifecycle_obligations=obligations,
        )
        with self.assertRaisesRegex(TargetAuthenticationContractError, "session-bound"):
            verify_target_authentication_chain(
                chain["provider"],
                chain["provenance"],
                chain["policy"],
                command,
                chain["evidence"],
                chain["result"],
            )
        with self.assertRaisesRegex(TargetAuthenticationContractError, "predecessor obligation"):
            _command_from(
                chain["command"],
                operation=AuthenticationOperation.REFRESH_SESSION,
                predecessor_session_ref="sessionref:test/old",
            )

    def test_failure_stage_and_result_pairing_are_closed(self) -> None:
        chain = _chain()
        evidence = chain["evidence"][0]
        with self.assertRaisesRegex(TargetAuthenticationContractError, "closed failure code"):
            TargetAuthenticationFlowEvidence(
                evidence.command_binding,
                evidence.provider_binding,
                evidence.execution_environment,
                FlowStage.FAILURE_OBSERVED,
                1,
                _digest("1"),
                None,
                None,
                None,
                None,
                evidence.observed_at,
            )
        with self.assertRaisesRegex(TargetAuthenticationContractError, "closed failure code"):
            TargetAuthenticationFlowEvidence(
                evidence.command_binding,
                evidence.provider_binding,
                evidence.execution_environment,
                FlowStage.SESSION_OBSERVED,
                1,
                _digest("1"),
                None,
                None,
                None,
                AuthenticationFailureCode.TIMEOUT,
                evidence.observed_at,
            )
        with self.assertRaisesRegex(TargetAuthenticationContractError, "unsuccessful result"):
            _result_from(
                chain["result"],
                outcome=AuthenticationOutcome.FAILED,
                failure_code=None,
                resulting_session_ref=None,
                session_evidence_sha256=None,
            )
        with self.assertRaisesRegex(TargetAuthenticationContractError, "stop failure code"):
            _result_from(
                chain["result"],
                outcome=AuthenticationOutcome.STOPPED,
                failure_code=AuthenticationFailureCode.TIMEOUT,
                resulting_session_ref=None,
                session_evidence_sha256=None,
            )

    def test_sequence_and_time_invariants_fail_verifier(self) -> None:
        chain = _chain()
        first = chain["evidence"][0]
        gap = TargetAuthenticationFlowEvidence(
            first.command_binding,
            first.provider_binding,
            first.execution_environment,
            first.stage,
            2,
            first.input_evidence_sha256,
            first.output_evidence_sha256,
            None,
            None,
            None,
            first.observed_at,
        )
        with self.assertRaisesRegex(TargetAuthenticationContractError, "sequence"):
            verify_target_authentication_chain(
                chain["provider"],
                chain["provenance"],
                chain["policy"],
                chain["command"],
                (gap,),
                chain["result"],
            )
        late = TargetAuthenticationFlowEvidence(
            first.command_binding,
            first.provider_binding,
            first.execution_environment,
            first.stage,
            1,
            first.input_evidence_sha256,
            first.output_evidence_sha256,
            None,
            None,
            None,
            "2026-09-20T10:10:00Z",
        )
        with self.assertRaisesRegex(TargetAuthenticationContractError, "times"):
            verify_target_authentication_chain(
                chain["provider"],
                chain["provenance"],
                chain["policy"],
                chain["command"],
                (late,),
                chain["result"],
            )

    def test_flow_stage_order_and_terminal_stage_invariants(self) -> None:
        def evidence_for(
            chain: dict[str, object],
            command: TargetAuthenticationCommand,
            stages: tuple[FlowStage, ...],
            *,
            failure_first: bool = False,
        ) -> tuple[TargetAuthenticationFlowEvidence, ...]:
            return tuple(
                TargetAuthenticationFlowEvidence(
                    command.content_binding,
                    chain["provider"].content_binding,
                    command.execution_environment,
                    stage,
                    index,
                    _digest(str(index)),
                    None,
                    None,
                    None,
                    (AuthenticationFailureCode.TIMEOUT if failure_first and index == 1 else None),
                    f"2026-09-20T10:0{index + 2}:00Z",
                )
                for index, stage in enumerate(stages, start=1)
            )

        oauth = _chain(
            mode=AuthenticationMode.OAUTH2_PKCE,
            topology=PrincipalTopology.FEDERATED_PRINCIPAL,
        )
        swapped = evidence_for(
            oauth,
            oauth["command"],
            (
                FlowStage.CREDENTIAL_REFERENCE_BOUND,
                FlowStage.CALLBACK_OBSERVED,
                FlowStage.REDIRECT_OBSERVED,
                FlowStage.SESSION_OBSERVED,
            ),
        )
        swapped_result = _result_from(
            oauth["result"],
            flow_evidence=tuple(item.content_binding for item in swapped),
            completed_at="2026-09-20T10:07:00Z",
        )
        with self.assertRaisesRegex(TargetAuthenticationContractError, "flow order"):
            verify_target_authentication_chain(
                oauth["provider"],
                oauth["provenance"],
                oauth["policy"],
                oauth["command"],
                swapped,
                swapped_result,
            )

        chain = _chain()
        nonterminal_session = evidence_for(
            chain,
            chain["command"],
            (
                FlowStage.CREDENTIAL_REFERENCE_BOUND,
                FlowStage.SESSION_OBSERVED,
                FlowStage.CHALLENGE_OBSERVED,
            ),
        )
        session_result = _result_from(
            chain["result"],
            flow_evidence=tuple(item.content_binding for item in nonterminal_session),
            completed_at="2026-09-20T10:06:00Z",
        )
        with self.assertRaisesRegex(TargetAuthenticationContractError, "flow order"):
            verify_target_authentication_chain(
                chain["provider"],
                chain["provenance"],
                chain["policy"],
                chain["command"],
                nonterminal_session,
                session_result,
            )

        terminate = _command_from(
            chain["command"],
            operation=AuthenticationOperation.TERMINATE_SESSION,
            requested_session_ref=None,
            predecessor_session_ref="sessionref:test/old",
        )
        nonterminal_termination = evidence_for(
            chain,
            terminate,
            (FlowStage.TERMINATION_OBSERVED, FlowStage.CREDENTIAL_REFERENCE_BOUND),
        )
        terminated_result = TargetAuthenticationResult(
            terminate.content_binding,
            chain["provider"].content_binding,
            ExecutionEnvironment.DETERMINISTIC_FIXTURE,
            AuthenticationOutcome.TERMINATED,
            None,
            tuple(item.content_binding for item in nonterminal_termination),
            None,
            None,
            None,
            None,
            terminate.lifecycle_obligations,
            (),
            "2026-09-20T10:06:00Z",
        )
        with self.assertRaisesRegex(TargetAuthenticationContractError, "terminal termination"):
            verify_target_authentication_chain(
                chain["provider"],
                chain["provenance"],
                chain["policy"],
                terminate,
                nonterminal_termination,
                terminated_result,
            )

        nonterminal_failure = evidence_for(
            chain,
            chain["command"],
            (FlowStage.FAILURE_OBSERVED, FlowStage.CREDENTIAL_REFERENCE_BOUND),
            failure_first=True,
        )
        failed_result = TargetAuthenticationResult(
            chain["command"].content_binding,
            chain["provider"].content_binding,
            ExecutionEnvironment.DETERMINISTIC_FIXTURE,
            AuthenticationOutcome.FAILED,
            AuthenticationFailureCode.TIMEOUT,
            tuple(item.content_binding for item in nonterminal_failure),
            None,
            None,
            None,
            None,
            (),
            chain["command"].lifecycle_obligations,
            "2026-09-20T10:06:00Z",
        )
        with self.assertRaisesRegex(TargetAuthenticationContractError, "terminal failure"):
            verify_target_authentication_chain(
                chain["provider"],
                chain["provenance"],
                chain["policy"],
                chain["command"],
                nonterminal_failure,
                failed_result,
            )

    def test_policy_command_and_result_time_windows_fail_closed(self) -> None:
        chain = _chain()
        command = _command_from(
            chain["command"],
            issued_at="2026-09-20T09:59:00Z",
            expires_at="2026-09-20T10:09:00Z",
        )
        with self.assertRaisesRegex(TargetAuthenticationContractError, "times"):
            verify_target_authentication_chain(
                chain["provider"],
                chain["provenance"],
                chain["policy"],
                command,
                chain["evidence"],
                chain["result"],
            )
        early_result = _result_from(chain["result"], completed_at="2026-09-20T10:03:00Z")
        with self.assertRaisesRegex(TargetAuthenticationContractError, "completion time"):
            verify_target_authentication_chain(
                chain["provider"],
                chain["provenance"],
                chain["policy"],
                chain["command"],
                chain["evidence"],
                early_result,
            )

    def test_duplicate_keys_unknown_fields_and_noncanonical_json_are_rejected(self) -> None:
        with self.assertRaisesRegex(TargetAuthenticationContractError, "duplicate key"):
            parse_target_authentication_record(
                '{"record_kind":"target_authentication_policy",'
                '"record_kind":"target_authentication_command"}'
            )
        raw = _chain()["policy"].to_dict()
        raw["unexpected"] = True
        with self.assertRaisesRegex(TargetAuthenticationContractError, "fields are invalid"):
            parse_target_authentication_policy(canonical_json(raw))
        document = canonical_json(_chain()["provider"].to_dict())
        with self.assertRaisesRegex(TargetAuthenticationContractError, "canonical JSON"):
            parse_target_authentication_provider_binding(document + " ")

    def test_unicode_dash_controls_and_unsupported_json_types_are_rejected(self) -> None:
        for value in ("bad\u2013dash", "bad\u2014dash", "bad\x00control"):
            with self.assertRaisesRegex(TargetAuthenticationContractError, "printable ASCII"):
                canonical_json({"value": value})
        with self.assertRaisesRegex(TargetAuthenticationContractError, "unsupported value"):
            canonical_json({"value": 1.5})

    def test_fixed_effect_and_claim_boundaries_are_immutable_and_serialized(self) -> None:
        self.assertIsInstance(NO_EFFECTS, MappingProxyType)
        self.assertIsInstance(NO_CLAIMS, MappingProxyType)
        with self.assertRaises(TypeError):
            NO_EFFECTS["network"] = "enabled"
        with self.assertRaises(TypeError):
            NO_CLAIMS["qualification"] = "qualified"
        for record in (_chain()["provider"], _chain()["receipt"]):
            self.assertEqual(record.to_dict()["effects"], dict(NO_EFFECTS))
            self.assertEqual(record.to_dict()["claims"], dict(NO_CLAIMS))

    def test_effect_claim_and_content_address_tampering_fail_closed(self) -> None:
        provider = _chain()["provider"]
        for field, key, value in (
            ("effects", "network", "enabled"),
            ("claims", "qualification", "qualified"),
        ):
            raw = copy.deepcopy(provider.to_dict())
            raw[field][key] = value
            with self.assertRaises(TargetAuthenticationContractError):
                parse_target_authentication_provider_binding(canonical_json(raw))
        raw = copy.deepcopy(provider.to_dict())
        raw["implementation_version"] = "2.0.0"
        with self.assertRaisesRegex(TargetAuthenticationContractError, "content address"):
            parse_target_authentication_provider_binding(canonical_json(raw))

    def test_receipt_rebinding_and_early_issue_time_fail_verifier(self) -> None:
        chain = _chain()
        other = _chain(external=True)
        receipt = TargetAuthenticationReceipt(
            provider_binding=chain["provider"].content_binding,
            policy_binding=chain["policy"].content_binding,
            command_binding=chain["command"].content_binding,
            result_binding=other["result"].content_binding,
            flow_evidence=tuple(item.content_binding for item in chain["evidence"]),
            execution_environment=ExecutionEnvironment.DETERMINISTIC_FIXTURE,
            lifecycle_complete=False,
            issued_at="2026-09-20T10:06:00Z",
        )
        with self.assertRaisesRegex(TargetAuthenticationContractError, "receipt chain"):
            verify_target_authentication_chain(
                chain["provider"],
                chain["provenance"],
                chain["policy"],
                chain["command"],
                chain["evidence"],
                chain["result"],
                receipt,
            )
        early = TargetAuthenticationReceipt(
            provider_binding=chain["provider"].content_binding,
            policy_binding=chain["policy"].content_binding,
            command_binding=chain["command"].content_binding,
            result_binding=chain["result"].content_binding,
            flow_evidence=tuple(item.content_binding for item in chain["evidence"]),
            execution_environment=ExecutionEnvironment.DETERMINISTIC_FIXTURE,
            lifecycle_complete=False,
            issued_at="2026-09-20T10:04:00Z",
        )
        with self.assertRaisesRegex(TargetAuthenticationContractError, "receipt chain"):
            verify_target_authentication_chain(
                chain["provider"],
                chain["provenance"],
                chain["policy"],
                chain["command"],
                chain["evidence"],
                chain["result"],
                early,
            )

    def test_public_and_compatibility_exports_when_present(self) -> None:
        public_names = (
            "TargetAuthenticationProviderBinding",
            "TargetCredentialProvenance",
            "TargetAuthenticationPolicy",
            "TargetAuthenticationCommand",
            "TargetAuthenticationFlowEvidence",
            "TargetAuthenticationResult",
            "TargetAuthenticationReceipt",
            "verify_target_authentication_chain",
        )
        direct = __import__(
            "sunderkey.target_authentication_adapter_contracts", fromlist=["unused"]
        )
        for package in (sunderkey,):
            for name in public_names:
                if hasattr(package, name):
                    self.assertIs(getattr(package, name), getattr(direct, name))


if __name__ == "__main__":
    unittest.main()

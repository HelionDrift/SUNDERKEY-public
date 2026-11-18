"""Phase 166 authenticated-target session contract coverage."""

from __future__ import annotations

import copy
import json
import unittest
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None

import sunderkey
from sunderkey.authenticated_target_contracts import (
    NO_EFFECTS,
    AdmissionStatus,
    AuthenticatedSessionContract,
    AuthenticatedTargetContractError,
    AuthenticationMethod,
    MFACheckpointEvidence,
    MFAStatus,
    MultiPrincipalAuthorizationPlan,
    NormalizedAuthenticatedResponse,
    OpaqueCredentialLease,
    PreparedAuthenticatedRequest,
    PrincipalAuthorizationCase,
    RedirectPKCEEvidence,
    RefreshEvidence,
    SessionAdmission,
    SessionContextBinding,
    SessionTerminationEvidence,
    TerminationReason,
    canonical_json,
    evaluate_session_admission,
    normalize_authenticated_response,
    parse_contract,
    prepare_authenticated_request,
    record_session_termination,
)

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "registry" / "schemas" / "authenticated-target-contract-v1.schema.json"
FILES = (
    ROOT / "src" / "sunderkey" / "authenticated_target_contracts.py",
    Path(__file__),
    SCHEMA,
    ROOT / "docs" / "authenticated-target-contracts.md",
)


def digest(character: str) -> str:
    return "sha256:" + character * 64


def context(*, session: str = "one", worker: str = "alpha", fence_epoch: int = 7):
    return SessionContextBinding(
        tenant_ref="tenantref:acme",
        mission_ref="missionref:assessment-44",
        scope_ref="scoperef:signed-v3",
        target_ref="targetref:app-one",
        worker_ref=f"workerref:{worker}",
        session_ref=f"sessionref:{session}",
        fence_ref="fenceref:mission-44",
        fencing_token_sha256=digest("f"),
        fence_epoch=fence_epoch,
    )


def lease(
    selected_context: SessionContextBinding,
    method: AuthenticationMethod,
    *,
    lease_ref: str = "leaseref:primary",
    revoked_at: str | None = None,
) -> OpaqueCredentialLease:
    return OpaqueCredentialLease(
        lease_ref=lease_ref,
        authentication_method=method,
        descriptor_sha256=digest("d"),
        principal_ref="principalref:alice",
        context_sha256=selected_context.context_sha256,
        issued_at="2026-09-20T10:00:00Z",
        expires_at="2026-09-20T18:00:00Z",
        revoked_at=revoked_at,
    )


def redirect(
    selected_context: SessionContextBinding,
    method: AuthenticationMethod,
) -> RedirectPKCEEvidence:
    return RedirectPKCEEvidence(
        protocol=method,
        evidence_ref="evidenceref:redirect-001",
        context_sha256=selected_context.context_sha256,
        state_sha256=digest("1"),
        pkce_challenge_sha256=digest("2"),
        redirect_uri_sha256=digest("3"),
        authorization_response_sha256=digest("4"),
        nonce_sha256=digest("5") if method is AuthenticationMethod.OIDC_PKCE else None,
        observed_at="2026-09-20T10:01:00Z",
        expires_at="2026-09-20T11:00:00Z",
    )


def mfa(selected_context: SessionContextBinding, status=MFAStatus.OPERATOR_CONFIRMED):
    return MFACheckpointEvidence(
        checkpoint_ref="checkpointref:mfa-001",
        operator_ref="operatorref:security-one",
        context_sha256=selected_context.context_sha256,
        challenge_sha256=digest("6"),
        status=status,
        observed_at="2026-09-20T10:02:00Z",
        expires_at="2026-09-20T11:00:00Z",
    )


def session(
    method: AuthenticationMethod = AuthenticationMethod.BASIC,
    *,
    selected_context: SessionContextBinding | None = None,
    revoked_at: str | None = None,
    mfa_status: MFAStatus | None = MFAStatus.OPERATOR_CONFIRMED,
    with_refresh: bool = False,
) -> AuthenticatedSessionContract:
    selected_context = selected_context or context()
    selected_lease = lease(selected_context, method, revoked_at=revoked_at)
    refresh_items = ()
    expires_at = "2026-09-20T12:00:00Z"
    if with_refresh:
        refresh_items = (
            RefreshEvidence(
                evidence_ref="evidenceref:refresh-001",
                context_sha256=selected_context.context_sha256,
                predecessor_lease_ref=selected_lease.lease_ref,
                successor_lease_ref="leaseref:rotated",
                exchange_sha256=digest("7"),
                observed_at="2026-09-20T10:30:00Z",
                expires_at="2026-09-20T18:00:00Z",
            ),
        )
        expires_at = "2026-09-20T18:30:00Z"
    return AuthenticatedSessionContract(
        context=selected_context,
        authentication_method=method,
        principal_ref="principalref:alice",
        lease=selected_lease,
        cookie_jar_ref=(
            "cookieref:isolated-alice" if method is AuthenticationMethod.COOKIE_SESSION else None
        ),
        isolation_nonce_sha256=digest("8"),
        redirect_evidence=(
            redirect(selected_context, method)
            if method in {AuthenticationMethod.OAUTH2_PKCE, AuthenticationMethod.OIDC_PKCE}
            else None
        ),
        mfa_checkpoint=mfa(selected_context, mfa_status) if mfa_status else None,
        refresh_evidence=refresh_items,
        issued_at="2026-09-20T10:03:00Z",
        expires_at=expires_at,
    )


def admission(selected_session: AuthenticatedSessionContract | None = None) -> SessionAdmission:
    selected_session = selected_session or session()
    return evaluate_session_admission(
        selected_session,
        selected_session.context,
        evaluated_at=datetime(2026, 9, 20, 10, 15, tzinfo=UTC),
        observed_fencing_token_sha256=digest("f"),
    )


def prepared_request() -> PreparedAuthenticatedRequest:
    return prepare_authenticated_request(
        admission(),
        method_sha256=digest("9"),
        request_target_sha256=digest("a"),
        header_value_sha256={"Authorization": digest("b"), "Cookie": digest("c")},
        body_sha256=digest("d"),
        prepared_at="2026-09-20T10:16:00Z",
        expires_at="2026-09-20T10:20:00Z",
    )


class AuthenticatedTargetContractTests(unittest.TestCase):
    def test_public_package_exports_are_available(self) -> None:
        self.assertIs(
            sunderkey.evaluate_authenticated_target_session,
            evaluate_session_admission,
        )
        self.assertIs(
            sunderkey.prepare_authenticated_request,
            prepare_authenticated_request,
        )
        self.assertIs(
            sunderkey.parse_authenticated_target_contract,
            parse_contract,
        )

    def test_basic_bearer_cookie_oauth_and_oidc_contracts_round_trip(self):
        for method in AuthenticationMethod:
            with self.subTest(method=method):
                record = session(method)
                self.assertEqual(parse_contract(record.to_dict()), record)
                self.assertEqual(record.to_dict()["effects"], dict(NO_EFFECTS))
                self.assertNotIn("credential", canonical_json(record.to_dict()).lower().split(":"))

    def test_content_addresses_are_stable_and_immutable(self):
        first = session()
        second = session()
        self.assertEqual(first.contract_id, second.contract_id)
        self.assertEqual(first.contract_sha256, second.contract_sha256)
        with self.assertRaises(FrozenInstanceError):
            first.principal_ref = "principalref:bob"

    def test_tamper_and_extra_fields_fail_closed(self):
        raw = session().to_dict()
        for mutation in ("principal", "digest", "extra", "effects"):
            candidate = copy.deepcopy(raw)
            if mutation == "principal":
                candidate["principal_ref"] = "principalref:bob"
            elif mutation == "digest":
                candidate["contract_sha256"] = digest("0")
            elif mutation == "extra":
                candidate["unexpected"] = True
            else:
                candidate["effects"]["network"] = "performed"
            with (
                self.subTest(mutation=mutation),
                self.assertRaises(AuthenticatedTargetContractError),
            ):
                parse_contract(candidate)

    def test_cross_context_components_are_rejected(self):
        primary = context()
        foreign = context(session="foreign", worker="bravo")
        for component in (
            {"lease": lease(foreign, AuthenticationMethod.BASIC)},
            {"mfa_checkpoint": mfa(foreign)},
        ):
            values = {
                "context": primary,
                "authentication_method": AuthenticationMethod.BASIC,
                "principal_ref": "principalref:alice",
                "lease": lease(primary, AuthenticationMethod.BASIC),
                "cookie_jar_ref": None,
                "isolation_nonce_sha256": digest("8"),
                "redirect_evidence": None,
                "mfa_checkpoint": mfa(primary),
                "refresh_evidence": (),
                "issued_at": "2026-09-20T10:03:00Z",
                "expires_at": "2026-09-20T12:00:00Z",
            }
            values.update(component)
            with self.assertRaises(AuthenticatedTargetContractError):
                AuthenticatedSessionContract(**values)

    def test_cookie_isolation_and_redirect_requirements_fail_closed(self):
        basic = session()
        with self.assertRaises(AuthenticatedTargetContractError):
            replace(basic, cookie_jar_ref="cookieref:leak")
        cookie = session(AuthenticationMethod.COOKIE_SESSION)
        with self.assertRaises(AuthenticatedTargetContractError):
            replace(cookie, cookie_jar_ref=None)
        oauth = session(AuthenticationMethod.OAUTH2_PKCE)
        with self.assertRaises(AuthenticatedTargetContractError):
            replace(oauth, redirect_evidence=None)
        with self.assertRaises(AuthenticatedTargetContractError):
            replace(redirect(context(), AuthenticationMethod.OIDC_PKCE), nonce_sha256=None)

    def test_refresh_rotates_lease_and_is_context_bound(self):
        record = session(with_refresh=True)
        self.assertEqual(record.active_lease_ref, "leaseref:rotated")
        with self.assertRaises(AuthenticatedTargetContractError):
            RefreshEvidence(
                evidence_ref="evidenceref:bad-refresh",
                context_sha256=record.context.context_sha256,
                predecessor_lease_ref="leaseref:same",
                successor_lease_ref="leaseref:same",
                exchange_sha256=digest("1"),
                observed_at="2026-09-20T10:30:00Z",
                expires_at="2026-09-20T11:00:00Z",
            )

    def test_admission_accepts_exact_current_context(self):
        result = admission()
        self.assertEqual(result.status, AdmissionStatus.ADMITTED)
        self.assertEqual(result.reason_refs, ())
        self.assertEqual(parse_contract(result.to_dict()), result)

    def test_admission_denies_cross_context_stale_fence_and_revocation(self):
        selected = session(revoked_at="2026-09-20T10:10:00Z")
        result = evaluate_session_admission(
            selected,
            context(session="different"),
            evaluated_at=datetime(2026, 9, 20, 13, 0, tzinfo=UTC),
            observed_fencing_token_sha256=digest("0"),
            revoked_lease_refs=(selected.active_lease_ref,),
        )
        self.assertEqual(result.status, AdmissionStatus.DENIED)
        self.assertIn("reasonref:context-mismatch", result.reason_refs)
        self.assertIn("reasonref:fence-mismatch", result.reason_refs)
        self.assertIn("reasonref:session-stale", result.reason_refs)
        self.assertIn("reasonref:lease-revoked", result.reason_refs)

    def test_admission_denies_declined_or_stale_mfa_and_redirect(self):
        selected = session(AuthenticationMethod.OIDC_PKCE, mfa_status=MFAStatus.OPERATOR_DECLINED)
        declined = evaluate_session_admission(
            selected,
            selected.context,
            evaluated_at=datetime(2026, 9, 20, 10, 15, tzinfo=UTC),
            observed_fencing_token_sha256=digest("f"),
        )
        self.assertIn("reasonref:mfa-not-confirmed", declined.reason_refs)
        stale = evaluate_session_admission(
            selected,
            selected.context,
            evaluated_at=datetime(2026, 9, 20, 11, 30, tzinfo=UTC),
            observed_fencing_token_sha256=digest("f"),
        )
        self.assertIn("reasonref:mfa-evidence-stale", stale.reason_refs)
        self.assertIn("reasonref:redirect-evidence-stale", stale.reason_refs)

    def test_denied_admission_cannot_prepare_request(self):
        selected = session()
        denied = evaluate_session_admission(
            selected,
            selected.context,
            evaluated_at=datetime(2026, 9, 20, 10, 15, tzinfo=UTC),
            observed_fencing_token_sha256=digest("0"),
        )
        with self.assertRaises(AuthenticatedTargetContractError):
            prepare_authenticated_request(
                denied,
                method_sha256=digest("1"),
                request_target_sha256=digest("2"),
                header_value_sha256={},
                body_sha256=None,
                prepared_at="2026-09-20T10:16:00Z",
                expires_at="2026-09-20T10:17:00Z",
            )

    def test_request_contains_header_digests_only_and_round_trips(self):
        request = prepared_request()
        self.assertEqual(set(request.header_value_sha256), {"authorization", "cookie"})
        self.assertTrue(
            all(value.startswith("sha256:") for value in request.header_value_sha256.values())
        )
        self.assertEqual(parse_contract(request.to_dict()), request)

    def test_response_normalization_is_digest_only_and_round_trips(self):
        request = prepared_request()
        response = normalize_authenticated_response(
            request,
            status_code=200,
            header_value_sha256={"Set-Cookie": digest("e")},
            body_sha256=digest("f"),
            body_size_bytes=128,
            received_at="2026-09-20T10:17:00Z",
        )
        self.assertIsInstance(response, NormalizedAuthenticatedResponse)
        self.assertEqual(parse_contract(response.to_dict()), response)
        with self.assertRaises(AuthenticatedTargetContractError):
            normalize_authenticated_response(
                request,
                status_code=200,
                header_value_sha256={},
                body_sha256=digest("1"),
                body_size_bytes=0,
                received_at="2026-09-20T10:00:00Z",
            )

    def test_multi_principal_plan_requires_negative_case_and_session_isolation(self):
        cases = (
            PrincipalAuthorizationCase(
                "caseref:owner-read",
                "principalref:owner",
                "sessionref:owner",
                digest("1"),
                digest("2"),
                digest("3"),
                True,
            ),
            PrincipalAuthorizationCase(
                "caseref:viewer-write",
                "principalref:viewer",
                "sessionref:viewer",
                digest("4"),
                digest("2"),
                digest("5"),
                False,
            ),
        )
        plan = MultiPrincipalAuthorizationPlan(
            "tenantref:acme",
            "missionref:assessment-44",
            "scoperef:signed-v3",
            "targetref:app-one",
            cases,
            "2026-09-20T10:00:00Z",
            "2026-09-20T18:00:00Z",
        )
        self.assertEqual(parse_contract(plan.to_dict()), plan)
        with self.assertRaises(AuthenticatedTargetContractError):
            replace(plan, cases=tuple(replace(case, expected_allowed=True) for case in cases))
        with self.assertRaises(AuthenticatedTargetContractError):
            replace(plan, cases=(cases[0], replace(cases[1], session_ref="sessionref:owner")))

    def test_termination_requires_reason_specific_evidence(self):
        selected = session()
        termination = record_session_termination(
            selected,
            reason=TerminationReason.LOGOUT,
            evidence_refs=("evidenceref:logout-response",),
            logout_observed=True,
            revocation_observed=False,
            terminated_at="2026-09-20T12:01:00Z",
        )
        self.assertIsInstance(termination, SessionTerminationEvidence)
        self.assertEqual(parse_contract(termination.to_dict()), termination)
        with self.assertRaises(AuthenticatedTargetContractError):
            replace(termination, logout_observed=False)
        with self.assertRaises(AuthenticatedTargetContractError):
            replace(
                termination,
                reason=TerminationReason.REVOKED,
                logout_observed=False,
                revocation_observed=False,
            )

    def test_secret_like_material_is_rejected(self):
        forbidden = (
            "Bearer abcdefghijklmnop",
            "Basic dXNlcjpwYXNz",
            "Cookie: session=abcdef",
            "otp=123456",
            "access_token=abcdefgh",
            "eyJabcdefgh.abcdefgh.abcdefgh",
        )
        for value in forbidden:
            with self.subTest(value=value), self.assertRaises(AuthenticatedTargetContractError):
                canonical_json({"value": value})
        with self.assertRaises(AuthenticatedTargetContractError):
            PreparedAuthenticatedRequest(
                admission_id=admission().admission_id,
                admission_sha256=admission().admission_sha256,
                context_sha256=context().context_sha256,
                method_sha256=digest("1"),
                request_target_sha256=digest("2"),
                header_value_sha256={"Authorization": "Bearer abcdefghijklmnop"},
                body_sha256=None,
                prepared_at="2026-09-20T10:16:00Z",
                expires_at="2026-09-20T10:20:00Z",
            )

    def test_time_windows_and_timezone_awareness_fail_closed(self):
        with self.assertRaises(AuthenticatedTargetContractError):
            replace(session(), expires_at="2026-09-20T10:03:00Z")
        with self.assertRaises(AuthenticatedTargetContractError):
            evaluate_session_admission(
                session(),
                context(),
                evaluated_at=datetime(2026, 9, 20, 10, 15),
                observed_fencing_token_sha256=digest("f"),
            )

    @unittest.skipIf(Draft202012Validator is None, "jsonschema is unavailable")
    def test_schema_accepts_every_top_level_record(self):
        validator = Draft202012Validator(json.loads(SCHEMA.read_text(encoding="utf-8")))
        selected_session = session()
        selected_admission = admission(selected_session)
        request = prepared_request()
        response = normalize_authenticated_response(
            request,
            status_code=204,
            header_value_sha256={},
            body_sha256=digest("0"),
            body_size_bytes=0,
            received_at="2026-09-20T10:17:00Z",
        )
        termination = record_session_termination(
            selected_session,
            reason=TerminationReason.OPERATOR_STOP,
            evidence_refs=("evidenceref:stop",),
            logout_observed=False,
            revocation_observed=False,
            terminated_at="2026-09-20T12:00:00Z",
        )
        case_one = PrincipalAuthorizationCase(
            "caseref:one",
            "principalref:one",
            "sessionref:one",
            digest("1"),
            digest("2"),
            digest("3"),
            True,
        )
        case_two = PrincipalAuthorizationCase(
            "caseref:two",
            "principalref:two",
            "sessionref:two",
            digest("4"),
            digest("5"),
            digest("6"),
            False,
        )
        plan = MultiPrincipalAuthorizationPlan(
            "tenantref:acme",
            "missionref:m",
            "scoperef:s",
            "targetref:t",
            (case_one, case_two),
            "2026-09-20T10:00:00Z",
            "2026-09-20T11:00:00Z",
        )
        for record in (selected_session, selected_admission, request, response, termination, plan):
            with self.subTest(kind=record.to_dict()["kind"]):
                validator.validate(record.to_dict())

    def test_files_are_ascii_and_have_no_unicode_dashes(self):
        for path in FILES:
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("\u2013", text, path)
            self.assertNotIn("\u2014", text, path)
            text.encode("ascii")


if __name__ == "__main__":
    unittest.main()

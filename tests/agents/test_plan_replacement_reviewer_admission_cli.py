"""Explicit local operator commands, without signing keys or target interactions."""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from unittest import mock

from sunderkey import cli
from sunderkey.errors import PrincipalAuthenticationError, StoreError
from sunderkey.identity import ScopeGrantRevocation, compute_operation_intent_hash
from sunderkey.plan_replacement_reviewer_admission import (
    REVIEWER_OPERATIONS,
    AuthenticatedPlanReplacementReviewerAdmissionService,
    load_plan_replacement_reviewer_admission_request,
)
from sunderkey.plan_replacement_reviewer_admission_intents import (
    load_plan_replacement_reviewer_admission_approval_intents,
)
from sunderkey.scope import ScopeGrantRevocationAcceptanceService
from sunderkey.store import MissionStore

from .test_plan_replacement_reviewer_admission import (
    AUDIENCE,
    MISSION_ID,
    NOW,
    POLICY_VERSION,
    REGISTRY_PATH,
    ZERO_SIGNATURE,
    ReviewerAdmissionFixture,
    b64url,
)

PREFIX = "collaboration-plan-replacement-reviewer-admission-"


def _json_file(path: Path, value) -> str:
    path.write_text(json.dumps(value), encoding="utf-8")
    return str(path)


def _run(arguments: list[str], *, at=NOW) -> str:
    output = io.StringIO()
    with (
        mock.patch("sys.argv", ["sunderkey", *arguments]),
        mock.patch.object(
            cli, "MissionStore", side_effect=lambda path: MissionStore(path, clock=lambda: at)
        ),
        redirect_stdout(output),
    ):
        cli.main()
    return output.getvalue()


def _store_arguments(fixture: ReviewerAdmissionFixture) -> list[str]:
    return ["--store", str(fixture.path), "--registry", str(REGISTRY_PATH)]


def _prepare_arguments(fixture, marker: int, profile: str, *, role="independent_control"):
    grant = fixture.grant(marker, profile, REVIEWER_OPERATIONS[role])
    grant_path = fixture.path.parent / f"grant-{marker}.json"
    output = fixture.path.parent / f"request-{marker}.json"
    arguments = [
        PREFIX + "prepare",
        *_store_arguments(fixture),
        "--mission-id",
        MISSION_ID,
        "--admission-id",
        f"RVA-{marker:032X}",
        "--reviewer-scope-grant",
        _json_file(grant_path, grant.to_dict()),
        "--reviewer-issuer",
        "identity-provider",
        "--reviewer-subject",
        grant.subject,
        "--role",
        role,
        "--issued-at",
        "2026-07-30T10:09:00Z",
        "--not-before",
        "2026-07-30T10:09:00Z",
        "--expires-at",
        "2026-07-30T10:25:00Z",
        "--output",
        str(output),
    ]
    return arguments, output


def _admit_arguments(fixture, request_path: Path, assertions, *, marker: int):
    return [
        PREFIX + "admit",
        *_store_arguments(fixture),
        "--request",
        str(request_path),
        "--mission-owner-assertion",
        _json_file(
            fixture.path.parent / f"owner-{marker}.json",
            assertions["mission_owner_assertion"].to_dict(),
        ),
        "--independent-control-assertion",
        _json_file(
            fixture.path.parent / f"control-{marker}.json",
            assertions["independent_control_assertion"].to_dict(),
        ),
    ]


class ReviewerAdmissionCLIParserTests(unittest.TestCase):
    def test_exclusive_publication_rejects_a_late_output_without_store_use(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "late-output.json"
            packet = mock.Mock()
            packet.to_dict.return_value = {"synthetic": "unsigned packet"}

            def build_packet(*args, **kwargs):
                output.write_bytes(b"late creator bytes\n")
                return packet

            arguments = [
                PREFIX + "approval-intents",
                "--request",
                "synthetic-request",
                "--mission-owner-profile-id",
                "owner",
                "--independent-control-profile-id",
                "control",
                "--output",
                str(output),
            ]
            with (
                mock.patch.object(cli, "load_plan_replacement_reviewer_admission_request"),
                mock.patch.object(
                    cli,
                    "build_plan_replacement_reviewer_admission_approval_intents",
                    side_effect=build_packet,
                ),
                mock.patch.object(cli, "_plan_replacement_reviewer_admission_service") as service,
                self.assertRaisesRegex(SystemExit, "already exists"),
            ):
                _run(arguments)
            self.assertEqual(output.read_bytes(), b"late creator bytes\n")
            service.assert_not_called()

    def test_all_inputs_are_explicit_and_roles_are_closed(self):
        parser = cli.build_parser()
        commands = {
            "prepare": [
                "--store",
                "store",
                "--registry",
                "registry",
                "--mission-id",
                "mission",
                "--admission-id",
                "admission",
                "--reviewer-scope-grant",
                "grant",
                "--reviewer-issuer",
                "issuer",
                "--reviewer-subject",
                "subject",
                "--role",
                "independent_control",
                "--issued-at",
                "issued",
                "--not-before",
                "start",
                "--expires-at",
                "end",
                "--output",
                "new-request",
            ],
            "approval-intents": [
                "--request",
                "request",
                "--mission-owner-profile-id",
                "owner",
                "--independent-control-profile-id",
                "control",
                "--output",
                "new-intents",
            ],
            "admit": [
                "--store",
                "store",
                "--registry",
                "registry",
                "--request",
                "request",
                "--mission-owner-assertion",
                "owner",
                "--independent-control-assertion",
                "control",
            ],
            "show": [
                "--store",
                "store",
                "--registry",
                "registry",
                "--mission-id",
                "mission",
                "--admission-id",
                "admission",
            ],
        }
        for action, tokens in commands.items():
            args = parser.parse_args([PREFIX + action, *tokens])
            self.assertTrue(callable(args.handler))
            for index in range(0, len(tokens), 2):
                with (
                    self.subTest(action=action, missing=tokens[index]),
                    redirect_stderr(io.StringIO()),
                ):
                    with self.assertRaises(SystemExit) as raised:
                        parser.parse_args([PREFIX + action, *tokens[:index], *tokens[index + 2 :]])
                    self.assertEqual(raised.exception.code, 2)
        for role in REVIEWER_OPERATIONS:
            tokens = list(commands["prepare"])
            tokens[tokens.index("--role") + 1] = role
            self.assertEqual(parser.parse_args([PREFIX + "prepare", *tokens]).role, role)
        tokens = list(commands["prepare"])
        tokens[tokens.index("--role") + 1] = "mission_owner"
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            parser.parse_args([PREFIX + "prepare", *tokens])

    def test_admit_has_no_output_or_signing_key_option(self):
        arguments = [
            PREFIX + "admit",
            "--store",
            "store",
            "--registry",
            "registry",
            "--request",
            "request",
            "--mission-owner-assertion",
            "owner",
            "--independent-control-assertion",
            "control",
        ]
        parser = cli.build_parser()
        self.assertFalse(hasattr(parser.parse_args(arguments), "output"))
        for option in ("--output", "--private-key", "--signing-key"):
            with self.subTest(option=option), redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    parser.parse_args([*arguments, option, "forbidden"])
                self.assertEqual(raised.exception.code, 2)

    def test_service_uses_only_explicit_store_and_registry(self):
        args = cli.build_parser().parse_args(
            [
                PREFIX + "show",
                "--store",
                "explicit.sqlite3",
                "--registry",
                "explicit-registry.json",
                "--mission-id",
                "mission",
                "--admission-id",
                "admission",
            ]
        )
        with (
            mock.patch.object(cli, "load_registry") as registry,
            mock.patch.object(cli, "MissionStore") as store,
            mock.patch.object(
                cli, "AuthenticatedPlanReplacementReviewerAdmissionService"
            ) as service,
        ):
            self.assertIs(
                cli._plan_replacement_reviewer_admission_service(args), service.return_value
            )
        registry.assert_called_once_with("explicit-registry.json")
        store.assert_called_once_with("explicit.sqlite3")
        service.assert_called_once_with(store.return_value, registry.return_value)

    def test_existing_outputs_fail_before_loading_inputs_or_store(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "existing.json"
            output.write_text("untouched\n", encoding="utf-8")
            original = output.read_bytes()
            cases = [
                [
                    PREFIX + "prepare",
                    "--store",
                    "missing-store",
                    "--registry",
                    "missing-registry",
                    "--mission-id",
                    "mission",
                    "--admission-id",
                    "admission",
                    "--reviewer-scope-grant",
                    "missing-grant",
                    "--reviewer-issuer",
                    "issuer",
                    "--reviewer-subject",
                    "subject",
                    "--role",
                    "second_control",
                    "--issued-at",
                    "issued",
                    "--not-before",
                    "start",
                    "--expires-at",
                    "end",
                    "--output",
                    str(output),
                ],
                [
                    PREFIX + "approval-intents",
                    "--request",
                    "missing-request",
                    "--mission-owner-profile-id",
                    "owner",
                    "--independent-control-profile-id",
                    "control",
                    "--output",
                    str(output),
                ],
            ]
            with (
                mock.patch.object(cli, "load_scope_grant") as grant,
                mock.patch.object(
                    cli, "load_plan_replacement_reviewer_admission_request"
                ) as request,
                mock.patch.object(cli, "_plan_replacement_reviewer_admission_service") as service,
            ):
                for arguments in cases:
                    with (
                        self.subTest(command=arguments[0]),
                        self.assertRaisesRegex(SystemExit, "already exists"),
                    ):
                        _run(arguments)
                    self.assertEqual(output.read_bytes(), original)
            grant.assert_not_called()
            request.assert_not_called()
            service.assert_not_called()

    def test_output_cannot_alias_the_request_or_signed_grant(self):
        with tempfile.TemporaryDirectory() as directory:
            input_path = Path(directory) / "input.json"
            input_path.write_text("protected\n", encoding="utf-8")
            original = input_path.read_bytes()
            cases = [
                [
                    PREFIX + "prepare",
                    "--store",
                    "store",
                    "--registry",
                    "registry",
                    "--mission-id",
                    "mission",
                    "--admission-id",
                    "admission",
                    "--reviewer-scope-grant",
                    str(input_path),
                    "--reviewer-issuer",
                    "issuer",
                    "--reviewer-subject",
                    "subject",
                    "--role",
                    "second_control",
                    "--issued-at",
                    "issued",
                    "--not-before",
                    "start",
                    "--expires-at",
                    "end",
                    "--output",
                    str(input_path),
                ],
                [
                    PREFIX + "approval-intents",
                    "--request",
                    str(input_path),
                    "--mission-owner-profile-id",
                    "owner",
                    "--independent-control-profile-id",
                    "control",
                    "--output",
                    str(input_path),
                ],
            ]
            for arguments in cases:
                with (
                    self.subTest(command=arguments[0]),
                    self.assertRaisesRegex(SystemExit, "must not replace"),
                ):
                    _run(arguments)
                self.assertEqual(input_path.read_bytes(), original)


class ReviewerAdmissionCLISignedFlowTests(unittest.TestCase):
    def test_signed_flow_intents_negative_inputs_and_historical_show(self):
        fixture = ReviewerAdmissionFixture(self)
        before = fixture.counts()
        prepare, request_path = _prepare_arguments(fixture, 300, "AOE-HQ-13")
        self.assertEqual(_run(prepare), "")
        request = load_plan_replacement_reviewer_admission_request(request_path)
        self.assertEqual(json.loads(request_path.read_text(encoding="utf-8")), request.to_dict())
        self.assertEqual(fixture.counts(), before)
        packet_path = fixture.path.parent / "approval-intents.json"
        self.assertEqual(
            _run(
                [
                    PREFIX + "approval-intents",
                    "--request",
                    str(request_path),
                    "--mission-owner-profile-id",
                    fixture.owner_profile,
                    "--independent-control-profile-id",
                    fixture.control_profile,
                    "--output",
                    str(packet_path),
                ]
            ),
            "",
        )
        packet = load_plan_replacement_reviewer_admission_approval_intents(packet_path).to_dict()
        self.assertEqual(packet["admission"], request.to_dict())
        self.assertEqual(packet["approval_status"], "unsigned")
        self.assertEqual(packet["approver_assignment"], "not_verified")
        for effect in (
            "authority_effect",
            "runtime_effect",
            "target_authority",
            "qualification_effect",
        ):
            self.assertEqual(packet[effect], "none")
        for intent in packet["approval_intents"].values():
            self.assertEqual(
                intent["operation_intent_sha256"],
                compute_operation_intent_hash(intent["operation"], intent["operation_intent"]),
            )
        self.assertEqual(fixture.counts(), before)
        approvals = fixture.approvals(request)
        admit = _admit_arguments(fixture, request_path, approvals, marker=400)
        owner_path = Path(admit[admit.index("--mission-owner-assertion") + 1])
        missing = list(admit)
        missing[missing.index("--mission-owner-assertion") + 1] = str(
            owner_path.with_name("missing.json")
        )
        substituted = list(admit)
        substituted[substituted.index("--independent-control-assertion") + 1] = str(owner_path)
        other = fixture.request(301, profile="AOE-HQ-15")
        wrong_request = _admit_arguments(
            fixture, request_path, fixture.approvals(other, 410), marker=410
        )
        for label, arguments in (
            ("missing", missing),
            ("role substitution", substituted),
            ("request substitution", wrong_request),
        ):
            with self.subTest(case=label), self.assertRaises(SystemExit):
                _run(arguments)
            self.assertEqual(fixture.counts(), before)
        receipt = json.loads(_run(admit))
        after = fixture.counts()
        self.assertEqual(after, (before[0] + 1, before[1] + 2, before[2] + 2, before[3] + 1))
        self.assertEqual(json.loads(_run(admit)), receipt)
        self.assertEqual(fixture.counts(), after)
        show = [
            PREFIX + "show",
            *_store_arguments(fixture),
            "--mission-id",
            MISSION_ID,
            "--admission-id",
            request.admission_id,
        ]
        historical = json.loads(_run(show, at=NOW + timedelta(minutes=16)))
        self.assertEqual(historical["receipt"], receipt)
        self.assertEqual(historical["verification_scope"], "historical_custody_only")
        self.assertIs(historical["current_authority_verified"], False)
        with self.assertRaises(SystemExit):
            _run(admit, at=NOW + timedelta(minutes=16))
        grant = request.scope_grant
        unsigned = ScopeGrantRevocation.from_dict(
            {
                "schema_version": 1,
                "revocation_id": "SRV-" + "A" * 32,
                "policy_id": fixture.policy.policy_id,
                "policy_version": POLICY_VERSION,
                "issuer": "reviewer-revocation-authority",
                "key_id": "REVOCATION-REVIEWERS",
                "audience": AUDIENCE,
                "store_id": fixture.store_id,
                "mission_id": MISSION_ID,
                "mission_context_hash": fixture.stored.context_hash,
                "scope_grant_issuer": grant.issuer,
                "scope_grant_id": grant.grant_id,
                "scope_grant_sha256": grant.content_sha256,
                "scope_grant_subject": grant.subject,
                "scope_grant_profile_id": grant.profile_id,
                "reason_code": "authorization_withdrawn",
                "reason": "Synthetic reviewer withdrawal.",
                "issued_at": "2026-07-30T10:10:00Z",
                "not_before": "2026-07-30T10:10:00Z",
                "expires_at": "2026-07-30T10:14:00Z",
                "signature": ZERO_SIGNATURE,
            }
        )
        signed = replace(
            unsigned, signature=b64url(fixture.revocation_private.sign(unsigned.signing_bytes()))
        )
        ScopeGrantRevocationAcceptanceService(fixture.store, fixture.registry).accept(signed)
        self.assertEqual(json.loads(_run(show))["receipt"], receipt)
        with self.assertRaises(SystemExit):
            _run(admit)
        self.assertEqual(fixture.counts(), after)
        with self.assertRaisesRegex(PrincipalAuthenticationError, "revoked"):
            fixture.current_use(request)

    def test_stale_fence_and_post_consumption_failure_are_atomic(self):
        fixture = ReviewerAdmissionFixture(self)
        requests = []
        for marker, profile in ((300, "AOE-HQ-13"), (301, "AOE-HQ-15")):
            arguments, path = _prepare_arguments(fixture, marker, profile)
            _run(arguments)
            request = load_plan_replacement_reviewer_admission_request(path)
            approval_marker = marker * 10
            approvals = fixture.approvals(request, approval_marker)
            requests.append(
                (request, _admit_arguments(fixture, path, approvals, marker=approval_marker))
            )
        _run(requests[0][1])
        before = fixture.counts()
        with self.assertRaisesRegex(SystemExit, "stale"):
            _run(requests[1][1])
        self.assertEqual(fixture.counts(), before)
        arguments, path = _prepare_arguments(fixture, 302, "AOE-HQ-15")
        _run(arguments)
        request = load_plan_replacement_reviewer_admission_request(path)
        admit = _admit_arguments(fixture, path, fixture.approvals(request, 420), marker=420)
        with (
            mock.patch.object(
                AuthenticatedPlanReplacementReviewerAdmissionService,
                "_insert_scope",
                side_effect=StoreError("synthetic post-consumption failure"),
            ) as insert,
            self.assertRaisesRegex(SystemExit, "post-consumption failure"),
        ):
            _run(admit)
        insert.assert_called_once()
        self.assertEqual(fixture.counts(), before)
        _run(admit)
        self.assertEqual(
            fixture.counts(), (before[0] + 1, before[1] + 2, before[2] + 2, before[3] + 1)
        )


if __name__ == "__main__":
    unittest.main()

"""Command line coverage for Phase 5 authenticated mission stops."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from sunderkey.cli import build_parser, main
from sunderkey.identity import (
    PrincipalOperation,
    PrincipalTrustPolicy,
    compute_operation_intent_hash,
)
from sunderkey.mission import MissionRequest
from sunderkey.store import canonical_json, format_timestamp, sha256_text

from .test_identity_phase4 import (
    ASSERTION_ID,
    AUDIENCE,
    PROFILE_ID,
    ROOT_KEY_ID,
    SCOPE_DOCUMENT_HASH,
    SCOPE_REFERENCE,
    ZERO_SIGNATURE,
    CredentialFactory,
    b64url,
    public_bytes,
)
from .test_store import REGISTRY_PATH, mission_data

MISSION_ID = "MISSION-CLI-PHASE5"
POLICY_VERSION = 7
STOP_ARGUMENTS = {
    "reason_code": "operator_request",
    "reason": "Operator requested an authenticated CLI stop",
    "risk": "Continued activity is outside the authorized decision",
    "decision_owner": "range-control",
    "idempotency_key": "phase5-cli-authenticated-stop",
    "expected_version": 1,
}


def run_cli_text(*arguments: str) -> str:
    output = io.StringIO()
    with (
        patch("sys.argv", ["sunderkey", *arguments]),
        redirect_stdout(output),
    ):
        main()
    return output.getvalue()


def run_cli(*arguments: str) -> dict[str, object]:
    return json.loads(run_cli_text(*arguments))


def write_json(path: Path, value: dict[str, object]) -> None:
    path.write_text(
        json.dumps(
            value,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ),
        encoding="utf-8",
        newline="\n",
    )


def command_parser(
    parser: argparse.ArgumentParser,
    command: str,
) -> argparse.ArgumentParser:
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return action.choices[command]
    raise AssertionError("CLI parser has no subcommands")


def signed_current_policy(
    factory: CredentialFactory,
    store_id: str,
    now: datetime,
) -> PrincipalTrustPolicy:
    not_before = format_timestamp(now - timedelta(minutes=5))
    expires_at = format_timestamp(now + timedelta(hours=2))
    policy = factory.policy(
        policy_version=POLICY_VERSION,
        store_id=store_id,
        key_not_before=not_before,
        key_not_after=expires_at,
        allowed_profiles=[PROFILE_ID],
        allowed_operations=[PrincipalOperation.MISSION_STOP.value],
    )
    raw = policy.to_dict()
    raw.update(
        {
            "issued_at": not_before,
            "not_before": not_before,
            "expires_at": expires_at,
            "signature": ZERO_SIGNATURE,
        }
    )
    unsigned = PrincipalTrustPolicy.from_dict(raw)
    return replace(
        unsigned,
        signature=b64url(
            factory.root_private.sign(unsigned.signing_bytes())
        ),
    )


class Phase5CliTests(unittest.TestCase):
    def test_authenticated_command_parser_contracts(self) -> None:
        parser = build_parser()
        scope_parser = command_parser(parser, "scope-accept")
        stop_parser = command_parser(
            parser,
            "mission-stop-authenticated",
        )

        scope_required = {
            action.dest
            for action in scope_parser._actions
            if getattr(action, "required", False)
        }
        self.assertEqual(
            scope_required,
            {"registry", "scope_grant", "store"},
        )

        stop_required = {
            action.dest
            for action in stop_parser._actions
            if getattr(action, "required", False)
        }
        self.assertEqual(
            stop_required,
            {
                "decision_owner",
                "expected_version",
                "idempotency_key",
                "mission_id",
                "principal_assertion",
                "reason",
                "reason_code",
                "registry",
                "risk",
                "store",
            },
        )
        stop_destinations = {
            action.dest for action in stop_parser._actions
        }
        self.assertNotIn("principal_profile_id", stop_destinations)
        expected_version = next(
            action
            for action in stop_parser._actions
            if action.dest == "expected_version"
        )
        self.assertIs(expected_version.type, int)

        parsed = parser.parse_args(
            [
                "mission-stop-authenticated",
                "--store",
                "missions.sqlite3",
                "--registry",
                "registry.json",
                "--principal-assertion",
                "assertion.json",
                "--mission-id",
                MISSION_ID,
                "--reason-code",
                STOP_ARGUMENTS["reason_code"],
                "--reason",
                STOP_ARGUMENTS["reason"],
                "--risk",
                STOP_ARGUMENTS["risk"],
                "--decision-owner",
                STOP_ARGUMENTS["decision_owner"],
                "--idempotency-key",
                STOP_ARGUMENTS["idempotency_key"],
                "--expected-version",
                str(STOP_ARGUMENTS["expected_version"]),
            ]
        )
        self.assertFalse(hasattr(parsed, "principal_profile_id"))

        error = io.StringIO()
        with (
            redirect_stderr(error),
            self.assertRaises(SystemExit),
        ):
            parser.parse_args(
                [
                    "mission-stop-authenticated",
                    "--store",
                    "missions.sqlite3",
                    "--registry",
                    "registry.json",
                    "--principal-assertion",
                    "assertion.json",
                    "--mission-id",
                    MISSION_ID,
                    "--reason-code",
                    STOP_ARGUMENTS["reason_code"],
                    "--reason",
                    STOP_ARGUMENTS["reason"],
                    "--risk",
                    STOP_ARGUMENTS["risk"],
                    "--decision-owner",
                    STOP_ARGUMENTS["decision_owner"],
                    "--idempotency-key",
                    STOP_ARGUMENTS["idempotency_key"],
                    "--expected-version",
                    str(STOP_ARGUMENTS["expected_version"]),
                    "--principal-profile-id",
                    PROFILE_ID,
                ]
            )
        self.assertIn(
            "unrecognized arguments: --principal-profile-id",
            error.getvalue(),
        )

    def test_root_public_key_value_can_start_with_a_hyphen(self) -> None:
        parsed = build_parser().parse_args(
            [
                "trust-pin-root",
                "--store",
                "missions.sqlite3",
                "--root-key-id",
                ROOT_KEY_ID,
                "--audience",
                AUDIENCE,
                "--root-public-key",
                "-" + ("A" * 42),
                "--expected-key-hash",
                "sha256:" + ("a" * 64),
            ]
        )

        self.assertEqual(parsed.root_public_key, "-" + ("A" * 42))

    def test_authenticated_help_exposes_no_signing_material_options(
        self,
    ) -> None:
        parser = build_parser()
        command_parsers = (
            command_parser(parser, "scope-accept"),
            command_parser(parser, "mission-stop-authenticated"),
        )
        help_text = "\n".join(
            command.format_help() for command in command_parsers
        ).lower()
        self.assertNotIn("--private-key", help_text)
        self.assertNotIn("--signing", help_text)

        option_strings = {
            option
            for command in command_parsers
            for action in command._actions
            for option in action.option_strings
        }
        self.assertFalse(
            any(
                "private-key" in option or "signing" in option
                for option in option_strings
            )
        )

    def test_authenticated_cli_path_is_public_key_only_and_replay_safe(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            store_path = directory / "missions.sqlite3"
            mission_path = directory / "mission.json"
            policy_path = directory / "policy.json"
            grant_path = directory / "scope-grant.json"
            assertion_path = directory / "principal-assertion.json"

            raw_mission = mission_data()
            raw_mission.update(
                {
                    "mission_id": MISSION_ID,
                    "scope_reference": SCOPE_REFERENCE,
                    "scope_document_hash": SCOPE_DOCUMENT_HASH,
                }
            )
            mission = MissionRequest.from_dict(raw_mission)
            write_json(mission_path, mission.to_dict())

            initialized = run_cli(
                "init-store",
                "--store",
                str(store_path),
            )
            store_id = str(initialized["store_id"])
            common = (
                "--store",
                str(store_path),
                "--registry",
                str(REGISTRY_PATH),
            )
            created = run_cli(
                "create-mission",
                *common,
                "--mission",
                str(mission_path),
            )

            now = datetime.now(UTC).replace(microsecond=0)
            factory = CredentialFactory()
            root_public_key = public_bytes(factory.root_private)
            run_cli(
                "trust-pin-root",
                "--store",
                str(store_path),
                "--root-key-id",
                ROOT_KEY_ID,
                "--audience",
                AUDIENCE,
                "--root-public-key",
                b64url(root_public_key),
                "--expected-key-hash",
                "sha256:"
                + hashlib.sha256(root_public_key).hexdigest(),
            )
            policy = signed_current_policy(factory, store_id, now)
            write_json(policy_path, policy.to_dict())
            applied = run_cli(
                "trust-apply-policy",
                "--store",
                str(store_path),
                "--policy",
                str(policy_path),
            )
            self.assertTrue(applied["policy_applied"])

            constraints_hash = sha256_text(
                canonical_json(mission.to_dict()["constraints"])
            )
            credential_start = format_timestamp(
                now - timedelta(minutes=1)
            )
            grant = factory.grant(
                profile_id=PROFILE_ID,
                store_id=store_id,
                mission_id=MISSION_ID,
                mission_context_hash=str(created["context_hash"]),
                scope_reference=SCOPE_REFERENCE,
                scope_document_hash=SCOPE_DOCUMENT_HASH,
                environment=mission.environment.value,
                max_action_tier=mission.max_action_tier.value,
                constraints_hash=constraints_hash,
                operations=[PrincipalOperation.MISSION_STOP.value],
                issued_at=credential_start,
                not_before=credential_start,
                expires_at=format_timestamp(
                    now + timedelta(minutes=29)
                ),
                policy_version=POLICY_VERSION,
            )
            write_json(grant_path, grant.to_dict())

            original_grant = grant_path.read_bytes()
            with self.assertRaisesRegex(
                SystemExit,
                "--output must not replace --scope-grant",
            ):
                run_cli(
                    "scope-accept",
                    *common,
                    "--scope-grant",
                    str(grant_path),
                    "--output",
                    str(grant_path),
                )
            self.assertEqual(grant_path.read_bytes(), original_grant)

            accepted = run_cli(
                "scope-accept",
                *common,
                "--scope-grant",
                str(grant_path),
            )
            self.assertEqual(
                accepted["grant"]["grant_id"],
                grant.grant_id,
            )
            self.assertFalse(accepted["idempotent"])

            intent_hash = compute_operation_intent_hash(
                PrincipalOperation.MISSION_STOP,
                {
                    "decision_owner": STOP_ARGUMENTS[
                        "decision_owner"
                    ],
                    "expected_version": STOP_ARGUMENTS[
                        "expected_version"
                    ],
                    "idempotency_key_sha256": sha256_text(
                        STOP_ARGUMENTS["idempotency_key"]
                    ),
                    "mission_id": MISSION_ID,
                    "principal_profile_id": PROFILE_ID,
                    "reason": STOP_ARGUMENTS["reason"],
                    "reason_code": STOP_ARGUMENTS["reason_code"],
                    "risk": STOP_ARGUMENTS["risk"],
                },
            )
            assertion = factory.assertion(
                grant=grant,
                assertion_id=ASSERTION_ID,
                policy_version=POLICY_VERSION,
                scope_grant_id=grant.grant_id,
                subject=grant.subject,
                profile_id=PROFILE_ID,
                audience=AUDIENCE,
                store_id=store_id,
                mission_id=MISSION_ID,
                operation=PrincipalOperation.MISSION_STOP,
                operation_intent_sha256=intent_hash,
                issued_at=credential_start,
                not_before=credential_start,
                expires_at=format_timestamp(
                    now + timedelta(minutes=4)
                ),
            )
            write_json(assertion_path, assertion.to_dict())

            original_assertion = assertion_path.read_bytes()
            with self.assertRaisesRegex(
                SystemExit,
                "--output must not replace --principal-assertion",
            ):
                run_cli(
                    "mission-stop-authenticated",
                    *common,
                    "--principal-assertion",
                    str(assertion_path),
                    "--mission-id",
                    MISSION_ID,
                    "--reason-code",
                    STOP_ARGUMENTS["reason_code"],
                    "--reason",
                    STOP_ARGUMENTS["reason"],
                    "--risk",
                    STOP_ARGUMENTS["risk"],
                    "--decision-owner",
                    STOP_ARGUMENTS["decision_owner"],
                    "--idempotency-key",
                    STOP_ARGUMENTS["idempotency_key"],
                    "--expected-version",
                    str(STOP_ARGUMENTS["expected_version"]),
                    "--output",
                    str(assertion_path),
                )
            self.assertEqual(
                assertion_path.read_bytes(),
                original_assertion,
            )

            stop_command = (
                "mission-stop-authenticated",
                *common,
                "--principal-assertion",
                str(assertion_path),
                "--mission-id",
                MISSION_ID,
                "--reason-code",
                STOP_ARGUMENTS["reason_code"],
                "--reason",
                STOP_ARGUMENTS["reason"],
                "--risk",
                STOP_ARGUMENTS["risk"],
                "--decision-owner",
                STOP_ARGUMENTS["decision_owner"],
                "--idempotency-key",
                STOP_ARGUMENTS["idempotency_key"],
                "--expected-version",
                str(STOP_ARGUMENTS["expected_version"]),
            )
            first_output = run_cli_text(*stop_command)
            retry_output = run_cli_text(*stop_command)
            self.assertEqual(
                retry_output.encode("utf-8"),
                first_output.encode("utf-8"),
            )
            receipt = json.loads(first_output)
            self.assertEqual(receipt["assertion_id"], ASSERTION_ID)
            self.assertEqual(
                receipt["mission_control"]["state"],
                "stopped",
            )
            self.assertNotIn("replayed", receipt)

            verified = run_cli("verify-store", *common)
            self.assertEqual(verified["status"], "valid")
            self.assertEqual(verified["mission_count"], 1)
            self.assertEqual(verified["event_count"], 1)


if __name__ == "__main__":
    unittest.main()

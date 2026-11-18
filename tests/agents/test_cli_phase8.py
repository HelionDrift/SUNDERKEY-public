"""Command-line coverage for authenticated Phase 8 event appends."""

from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sunderkey.cli import (
    build_parser as legacy_build_parser,
)
from sunderkey.authenticated_events import compute_event_batch_hash
from sunderkey.cli import build_parser
from sunderkey.events import MissionEvent
from sunderkey.identity import (
    PrincipalAssertion,
    PrincipalOperation,
    PrincipalTrustPolicy,
    ScopeGrant,
    compute_operation_intent_hash,
)
from sunderkey.mission import MissionRequest
from sunderkey.store import canonical_json, format_timestamp, sha256_text

from .test_cli_phase5 import run_cli, run_cli_text, write_json
from .test_identity_phase4 import (
    ASSERTION_ID,
    AUDIENCE,
    OTHER_ASSERTION_ID,
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

MISSION_ID = "MISSION-CLI-PHASE8"
OTHER_MISSION_ID = "MISSION-CLI-PHASE8-OTHER"
POLICY_VERSION = 7


def command_parser(
    parser: argparse.ArgumentParser,
    command: str,
) -> argparse.ArgumentParser:
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return action.choices[command]
    raise AssertionError("CLI parser has no subcommands")


def signed_event_policy(
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
        allowed_operations=[PrincipalOperation.EVENT_APPEND.value],
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


def event(
    event_id: str,
    *,
    timestamp: str,
) -> MissionEvent:
    return MissionEvent.from_dict(
        {
            "schema_version": 1,
            "event_id": event_id,
            "mission_id": MISSION_ID,
            "event_type": "observation",
            "actor_profile_id": PROFILE_ID,
            "timestamp": timestamp,
            "payload": {
                "target": f"synthetic://phase8-cli/{event_id.lower()}",
                "evidence_refs": [
                    f"evidence://phase8-cli/{event_id.lower()}"
                ],
                "confidence": "high",
                "sensitivity": "synthetic",
            },
            "references": [],
        }
    )


def write_events(path: Path, events: tuple[MissionEvent, ...]) -> None:
    path.write_text(
        "".join(
            json.dumps(
                item.to_dict(),
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
            for item in events
        ),
        encoding="utf-8",
        newline="\n",
    )


def signed_event_assertion(
    factory: CredentialFactory,
    grant: ScopeGrant,
    store_id: str,
    events: tuple[MissionEvent, ...],
    *,
    expected_revision: int,
    assertion_id: str,
    now: datetime,
) -> PrincipalAssertion:
    operation_intent_sha256 = compute_operation_intent_hash(
        PrincipalOperation.EVENT_APPEND,
        {
            "event_batch_sha256": compute_event_batch_hash(events),
            "expected_revision": expected_revision,
            "mission_id": MISSION_ID,
            "principal_profile_id": PROFILE_ID,
        },
    )
    return factory.assertion(
        grant=grant,
        assertion_id=assertion_id,
        policy_version=POLICY_VERSION,
        scope_grant_id=grant.grant_id,
        subject=grant.subject,
        profile_id=PROFILE_ID,
        audience=AUDIENCE,
        store_id=store_id,
        mission_id=MISSION_ID,
        operation=PrincipalOperation.EVENT_APPEND,
        operation_intent_sha256=operation_intent_sha256,
        issued_at=format_timestamp(now - timedelta(minutes=1)),
        not_before=format_timestamp(now - timedelta(minutes=1)),
        expires_at=format_timestamp(now + timedelta(minutes=4)),
    )


class Phase8CliTests(unittest.TestCase):
    def test_authenticated_event_parser_contract(self) -> None:
        parser = command_parser(
            build_parser(),
            "event-append-authenticated",
        )
        required = {
            action.dest
            for action in parser._actions
            if getattr(action, "required", False)
        }
        self.assertEqual(
            required,
            {
                "events",
                "expected_revision",
                "mission_id",
                "principal_assertion",
                "registry",
                "store",
            },
        )

        destinations = {action.dest for action in parser._actions}
        for forbidden in (
            "idempotency_key",
            "principal_profile_id",
            "private_key",
            "signing_key",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, destinations)

        option_strings = {
            option
            for action in parser._actions
            for option in action.option_strings
        }
        for forbidden in (
            "--idempotency-key",
            "--principal-profile-id",
            "--private-key",
            "--signing-key",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, option_strings)

        expected_revision = next(
            action
            for action in parser._actions
            if action.dest == "expected_revision"
        )
        self.assertIs(expected_revision.type, int)

    def test_command_is_exposed_by_current_and_compatibility_clis(
        self,
    ) -> None:
        current = command_parser(
            build_parser(),
            "event-append-authenticated",
        )
        legacy = command_parser(
            legacy_build_parser(),
            "event-append-authenticated",
        )

        self.assertEqual(
            {
                option
                for action in legacy._actions
                for option in action.option_strings
            },
            {
                option
                for action in current._actions
                for option in action.option_strings
            },
        )
        top_level_help = build_parser().format_help().lower()
        self.assertIn("event-append-authenticated", top_level_help)
        self.assertIn("signed principal assertion", top_level_help)

    def test_migrate_help_names_every_v8_source_version(self) -> None:
        help_text = " ".join(build_parser().format_help().split())

        self.assertIn(
            (
                "Migrate a verified v1 through v15 mission store to v16"
            ),
            help_text,
        )

    def test_output_cannot_replace_event_or_assertion_input(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            store_path = directory / "missions.sqlite3"
            event_path = directory / "events.jsonl"
            assertion_path = directory / "principal-assertion.json"
            event_path.write_text("event input\n", encoding="utf-8")
            assertion_path.write_text(
                "assertion input\n",
                encoding="utf-8",
            )

            protected = (
                ("events", event_path),
                ("principal-assertion", assertion_path),
            )
            for option, path in protected:
                with self.subTest(option=option):
                    original = path.read_bytes()
                    with self.assertRaisesRegex(
                        SystemExit,
                        f"--output must not replace --{option}",
                    ):
                        run_cli(
                            "event-append-authenticated",
                            "--store",
                            str(store_path),
                            "--registry",
                            str(REGISTRY_PATH),
                            "--principal-assertion",
                            str(assertion_path),
                            "--events",
                            str(event_path),
                            "--mission-id",
                            MISSION_ID,
                            "--expected-revision",
                            "0",
                            "--output",
                            str(path),
                        )
                    self.assertEqual(path.read_bytes(), original)

    def test_authenticated_single_batch_retry_and_direct_gate(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            store_path = directory / "missions.sqlite3"
            mission_path = directory / "mission.json"
            policy_path = directory / "policy.json"
            grant_path = directory / "scope-grant.json"
            assertion_path = directory / "principal-assertion.json"
            events_path = directory / "events.jsonl"

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
                "sha256:" + hashlib.sha256(root_public_key).hexdigest(),
            )
            policy = signed_event_policy(factory, store_id, now)
            write_json(policy_path, policy.to_dict())
            applied = run_cli(
                "trust-apply-policy",
                "--store",
                str(store_path),
                "--policy",
                str(policy_path),
            )
            self.assertTrue(applied["policy_applied"])

            event_timestamp = format_timestamp(
                now - timedelta(seconds=1)
            )
            single = (
                event(
                    "EVT-CLI-PHASE8-SINGLE",
                    timestamp=event_timestamp,
                ),
            )
            write_events(events_path, single)
            with self.assertRaisesRegex(
                SystemExit,
                "Direct event append is disabled",
            ):
                run_cli(
                    "append-events",
                    *common,
                    "--events",
                    str(events_path),
                    "--expected-revision",
                    "0",
                )

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
                operations=[PrincipalOperation.EVENT_APPEND.value],
                issued_at=credential_start,
                not_before=credential_start,
                expires_at=format_timestamp(
                    now + timedelta(minutes=29)
                ),
                policy_version=POLICY_VERSION,
            )
            write_json(grant_path, grant.to_dict())
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

            assertion = signed_event_assertion(
                factory,
                grant,
                store_id,
                single,
                expected_revision=0,
                assertion_id=ASSERTION_ID,
                now=now,
            )
            write_json(assertion_path, assertion.to_dict())
            command = (
                "event-append-authenticated",
                *common,
                "--principal-assertion",
                str(assertion_path),
                "--events",
                str(events_path),
                "--mission-id",
                MISSION_ID,
                "--expected-revision",
                "0",
            )

            with self.assertRaisesRegex(
                SystemExit,
                "command mission ID does not match the event batch",
            ):
                run_cli(
                    *command[:-3],
                    OTHER_MISSION_ID,
                    *command[-2:],
                )

            first_output = run_cli_text(*command)
            retry_output = run_cli_text(*command)
            self.assertEqual(
                retry_output.encode("utf-8"),
                first_output.encode("utf-8"),
            )
            first = json.loads(first_output)
            self.assertEqual(first["assertion_id"], ASSERTION_ID)
            self.assertEqual(first["mission_id"], MISSION_ID)
            self.assertEqual(
                [item["event_id"] for item in first["receipts"]],
                [single[0].event_id],
            )

            batch = (
                event(
                    "EVT-CLI-PHASE8-BATCH-A",
                    timestamp=event_timestamp,
                ),
                event(
                    "EVT-CLI-PHASE8-BATCH-B",
                    timestamp=event_timestamp,
                ),
            )
            write_events(events_path, batch)
            batch_assertion = signed_event_assertion(
                factory,
                grant,
                store_id,
                batch,
                expected_revision=1,
                assertion_id=OTHER_ASSERTION_ID,
                now=now,
            )
            write_json(assertion_path, batch_assertion.to_dict())
            batch_command = (
                "event-append-authenticated",
                *common,
                "--principal-assertion",
                str(assertion_path),
                "--events",
                str(events_path),
                "--mission-id",
                MISSION_ID,
                "--expected-revision",
                "1",
            )
            batch_output = run_cli_text(*batch_command)
            batch_retry = run_cli_text(*batch_command)
            self.assertEqual(
                batch_retry.encode("utf-8"),
                batch_output.encode("utf-8"),
            )
            appended = json.loads(batch_output)
            self.assertEqual(
                [item["event_id"] for item in appended["receipts"]],
                [item.event_id for item in batch],
            )
            self.assertEqual(
                [item["sequence"] for item in appended["receipts"]],
                [2, 3],
            )

            verified = run_cli("verify-store", *common)
            self.assertEqual(verified["status"], "valid")
            self.assertEqual(verified["mission_count"], 1)
            self.assertEqual(verified["event_count"], 3)


if __name__ == "__main__":
    unittest.main()

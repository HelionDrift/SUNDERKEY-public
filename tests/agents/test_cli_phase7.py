"""Command-line contracts for signed scope-grant revocation."""

from __future__ import annotations

import argparse
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sunderkey.cli import build_parser, main


def command_parser(
    parser: argparse.ArgumentParser,
    command: str,
) -> argparse.ArgumentParser:
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return action.choices[command]
    raise AssertionError("CLI parser has no subcommands")


class Phase7CliTests(unittest.TestCase):
    def test_migrate_help_names_every_v8_source_version(self) -> None:
        help_text = " ".join(build_parser().format_help().split())

        self.assertIn(
            (
                "Migrate a verified v1 through v15 mission store to v16"
            ),
            help_text,
        )

    def test_scope_revoke_parser_is_signed_artifact_only(self) -> None:
        parser = command_parser(build_parser(), "scope-revoke")
        required = {
            action.dest
            for action in parser._actions
            if getattr(action, "required", False)
        }
        self.assertEqual(
            required,
            {"registry", "scope_grant_revocation", "store"},
        )
        destinations = {
            action.dest for action in parser._actions
        }
        for forbidden in (
            "grant_id",
            "idempotency_key",
            "mission_id",
            "principal_profile_id",
            "reason",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, destinations)

        help_text = parser.format_help().lower()
        self.assertNotIn("--private-key", help_text)
        self.assertNotIn("--signing", help_text)

    def test_output_cannot_replace_signed_revocation_input(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "revocation.json"
            path.write_text("signed input", encoding="utf-8")
            original = path.read_bytes()

            with (
                patch(
                    "sys.argv",
                    [
                        "sunderkey",
                        "scope-revoke",
                        "--store",
                        str(Path(temporary) / "store.sqlite3"),
                        "--registry",
                        "registry.json",
                        "--scope-grant-revocation",
                        str(path),
                        "--output",
                        str(path),
                    ],
                ),
                self.assertRaisesRegex(
                    SystemExit,
                    "--output must not replace "
                    "--scope-grant-revocation",
                ),
            ):
                main()

            self.assertEqual(path.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()

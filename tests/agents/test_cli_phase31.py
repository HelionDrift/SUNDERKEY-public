"""Command-line coverage for the approved Phase 31 D008 record."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sunderkey.cli import build_parser as legacy_build_parser
from sunderkey.cli import build_parser, main

from .test_cli_phase9 import (
    command_parser,
    option_strings,
    required_destinations,
)

ROOT = Path(__file__).resolve().parents[2]
DOSSIER_PATH = ROOT / "registry" / "qualification-authority-dossier-d008.json"


class Phase31CliTests(unittest.TestCase):
    def test_command_contract_is_closed(self) -> None:
        command = command_parser(
            build_parser(),
            "qualification-authority-decision",
        )
        self.assertEqual(required_destinations(command), {"dossier"})
        self.assertFalse(
            option_strings(command)
            & {
                "--actor",
                "--decision",
                "--endpoint",
                "--evidence",
                "--issuer",
                "--model",
                "--principal-assertion",
                "--private-key",
                "--provider",
                "--reviewer",
                "--secret",
                "--signing-key",
                "--store",
                "--target",
                "--tool",
                "--worker",
            }
        )

    def test_current_and_compatibility_commands_match(self) -> None:
        current = command_parser(
            build_parser(),
            "qualification-authority-decision",
        )
        legacy = command_parser(
            legacy_build_parser(),
            "qualification-authority-decision",
        )
        self.assertEqual(option_strings(legacy), option_strings(current))
        self.assertEqual(
            required_destinations(legacy),
            required_destinations(current),
        )

    def test_output_cannot_replace_dossier(self) -> None:
        arguments = [
            "sunderkey",
            "qualification-authority-decision",
            "--dossier",
            "decision.json",
            "--output",
            "decision.json",
        ]
        with (
            patch("sys.argv", arguments),
            self.assertRaisesRegex(
                SystemExit,
                "Validation error: --output must not replace --dossier",
            ),
        ):
            main()

    def test_command_writes_the_approved_record(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "decision.json"
            arguments = [
                "sunderkey",
                "qualification-authority-decision",
                "--dossier",
                str(DOSSIER_PATH),
                "--output",
                str(output),
            ]
            with patch("sys.argv", arguments):
                main()
            document = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(document["decision_id"], "D008")
        self.assertEqual(document["decision_status"], "approved")
        self.assertEqual(
            document["record_id"],
            "QDR-7242E7ED90734BBE96A8036647FA227F",
        )


if __name__ == "__main__":
    unittest.main()

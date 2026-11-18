"""Command line coverage for deterministic collaboration plans."""

from __future__ import annotations

import importlib
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from sunderkey import cli
from sunderkey.cli import build_parser, main

ROOT = Path(__file__).resolve().parents[2]
REGISTRY_PATH = ROOT / "registry" / "army-v1.json"
MISSION_PATH = ROOT / "examples" / "missions" / "internet-api-to-data.json"
PLAN_PATH = (
    ROOT
    / "examples"
    / "collaboration"
    / "internet-api-to-data.json"
)


def run_cli_text(*arguments: str) -> str:
    output = io.StringIO()
    with (
        patch("sys.argv", ["sunderkey", *arguments]),
        redirect_stdout(output),
    ):
        main()
    return output.getvalue()


class Phase6CliTests(unittest.TestCase):
    def test_parser_requires_registry_and_mission(self) -> None:
        parser = build_parser()
        subcommand = None
        for action in parser._actions:
            if action.__class__.__name__ == "_SubParsersAction":
                subcommand = action.choices["plan-collaboration"]
                break
        self.assertIsNotNone(subcommand)
        required = {
            action.dest
            for action in subcommand._actions
            if getattr(action, "required", False)
        }
        self.assertEqual(required, {"registry", "mission"})

    def test_stdout_is_deterministic_canonical_presentation(self) -> None:
        arguments = (
            "plan-collaboration",
            "--registry",
            str(REGISTRY_PATH),
            "--mission",
            str(MISSION_PATH),
        )
        first = run_cli_text(*arguments)
        second = run_cli_text(*arguments)
        parsed = json.loads(first)

        self.assertEqual(first, second)
        self.assertEqual(first, PLAN_PATH.read_text(encoding="utf-8"))
        self.assertEqual(
            first,
            json.dumps(
                parsed,
                indent=2,
                sort_keys=True,
                ensure_ascii=True,
            )
            + "\n",
        )
        self.assertEqual(parsed["mission_id"], "EXAMPLE-API-DATA-001")
        self.assertEqual(len(parsed["work_items"]), 13)

    def test_output_file_matches_stdout_and_writes_no_database(self) -> None:
        expected = run_cli_text(
            "plan-collaboration",
            "--registry",
            str(REGISTRY_PATH),
            "--mission",
            str(MISSION_PATH),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output_path = root / "nested" / "collaboration-plan.json"
            output_path.parent.mkdir(parents=True)
            output_path.write_text("stale output\n", encoding="utf-8")
            captured = run_cli_text(
                "plan-collaboration",
                "--registry",
                str(REGISTRY_PATH),
                "--mission",
                str(MISSION_PATH),
                "--output",
                str(output_path),
            )

            self.assertEqual(captured, "")
            self.assertEqual(output_path.read_text(encoding="utf-8"), expected)
            self.assertEqual(
                tuple(path for path in root.rglob("*") if path.is_file()),
                (output_path,),
            )

    def test_json_writer_does_not_resolve_the_destination_leaf(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output_path = Path(temporary) / "plan.json"
            with patch.object(
                Path,
                "resolve",
                side_effect=AssertionError(
                    "destination leaf must remain lexical"
                ),
            ):
                cli._write_json({"written": True}, str(output_path))

            self.assertEqual(
                json.loads(output_path.read_text(encoding="utf-8")),
                {"written": True},
            )

    def test_output_cannot_replace_registry_or_mission_input(self) -> None:
        for protected_name, source_path, option in (
            ("registry", REGISTRY_PATH, "--registry"),
            ("mission", MISSION_PATH, "--mission"),
        ):
            with (
                self.subTest(protected_name=protected_name),
                tempfile.TemporaryDirectory() as temporary,
            ):
                protected_path = Path(temporary) / source_path.name
                original = source_path.read_bytes()
                protected_path.write_bytes(original)
                registry_path = (
                    protected_path
                    if protected_name == "registry"
                    else REGISTRY_PATH
                )
                mission_path = (
                    protected_path
                    if protected_name == "mission"
                    else MISSION_PATH
                )

                with self.assertRaisesRegex(
                    SystemExit,
                    f"--output must not replace {option}",
                ):
                    run_cli_text(
                        "plan-collaboration",
                        "--registry",
                        str(registry_path),
                        "--mission",
                        str(mission_path),
                        "--output",
                        str(protected_path),
                    )
                self.assertEqual(protected_path.read_bytes(), original)

    def test_legacy_module_aliases_the_canonical_collaboration_module(self) -> None:
        self.assertIs(
            importlib.import_module("sunderkey.collaboration"),
            importlib.import_module("sunderkey.collaboration"),
        )


if __name__ == "__main__":
    unittest.main()

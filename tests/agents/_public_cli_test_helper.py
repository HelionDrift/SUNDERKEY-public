"""Shared CLI invocation helper for public tests."""

from contextlib import redirect_stdout
import io
import json
from unittest.mock import patch

from sunderkey.cli import main


def run_cli(*arguments: str) -> dict[str, object]:
    output = io.StringIO()
    with patch("sys.argv", ["sunderkey", *arguments]), redirect_stdout(output):
        main()
    text = output.getvalue()
    return json.loads(text) if text else {}

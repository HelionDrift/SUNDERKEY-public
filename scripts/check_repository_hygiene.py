from __future__ import annotations

import argparse
import sys
from pathlib import Path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Check repository text hygiene")
    parser.add_argument("--root", default=".")
    return parser


def main() -> None:
    project_root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(project_root / "src"))
    from sunderkey.content_guard import require_clean_repository_text
    from sunderkey.errors import ContentPolicyError

    args = build_parser().parse_args()
    root = Path(args.root).resolve()
    try:
        require_clean_repository_text(root)
    except ContentPolicyError as exc:
        raise SystemExit(str(exc)) from exc
    print(f"Repository text policy passed: {root}")


if __name__ == "__main__":
    main()

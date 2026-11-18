"""Build the decision-bound collaboration reconfiguration policy."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from sunderkey.collaboration_authority_decision import (
    load_collaboration_authority_decision_record,
)
from sunderkey.collaboration_reconfiguration_policy import (
    build_collaboration_reconfiguration_authority_policy,
)


def build_parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[1]
    registry = root / "registry"
    parser = argparse.ArgumentParser(description="Build the reconfiguration policy")
    parser.add_argument(
        "--decision",
        default=str(registry / "collaboration-authority-decision-d001-d005.json"),
    )
    parser.add_argument(
        "--output",
        default=str(registry / "collaboration-reconfiguration-policy-d001-d005.json"),
    )
    return parser


def build_policy(args: argparse.Namespace) -> dict[str, object]:
    return build_collaboration_reconfiguration_authority_policy(
        load_collaboration_authority_decision_record(args.decision)
    ).to_dict()


def main() -> None:
    args = build_parser().parse_args()
    policy = build_policy(args)
    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(policy, ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(f"Wrote {policy['policy_id']}: {output}")


if __name__ == "__main__":
    main()

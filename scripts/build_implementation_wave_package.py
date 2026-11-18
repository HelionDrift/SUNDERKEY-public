"""Build one deterministic implementation wave selection report."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from sunderkey.implementation_work_packages import (
    load_implementation_work_package_report,
    select_implementation_wave_package,
)


def build_parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(
        description="Build one exact implementation wave package"
    )
    parser.add_argument(
        "--packages",
        default=str(
            root
            / "registry"
            / "implementation-work-packages-army-v1.json"
        ),
    )
    parser.add_argument("--wave-id", default="IW-001")
    parser.add_argument(
        "--output",
        default=str(
            root
            / "examples"
            / "implementation"
            / "iw-001-work-package.json"
        ),
    )
    return parser


def build_report(args: argparse.Namespace) -> dict[str, object]:
    work_packages = load_implementation_work_package_report(args.packages)
    return select_implementation_wave_package(
        work_packages,
        args.wave_id,
    ).to_dict()


def main() -> None:
    args = build_parser().parse_args()
    report = build_report(args)
    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(report, ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(
        "Wrote "
        f"{report['selected_wave_id']} with "
        f"{report['summary']['work_item_count']} work items: {output}"
    )


if __name__ == "__main__":
    main()

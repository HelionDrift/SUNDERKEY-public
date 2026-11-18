"""Check that every inert specialist fixture is declared and source-bound."""

from __future__ import annotations

import json
from pathlib import Path

from sunderkey.offline_specialist_components import CATALOG_PATH, INTEGRATION_PATHS

ROOT = Path(__file__).resolve().parents[1]


def check_fixture_manifest(
    *,
    fixture_paths: set[str],
    declared_paths: list[str],
    bound_paths: list[str],
) -> int:
    if len(declared_paths) != len(set(declared_paths)):
        raise ValueError("specialist fixture declarations contain duplicates")
    if len(bound_paths) != len(set(bound_paths)):
        raise ValueError("specialist fixture source bindings contain duplicates")
    if set(declared_paths) != fixture_paths:
        missing = sorted(fixture_paths - set(declared_paths))
        extra = sorted(set(declared_paths) - fixture_paths)
        raise ValueError(
            f"specialist fixture declarations differ: missing={missing}, extra={extra}"
        )
    if set(bound_paths) != fixture_paths:
        missing = sorted(fixture_paths - set(bound_paths))
        extra = sorted(set(bound_paths) - fixture_paths)
        raise ValueError(f"specialist fixture bindings differ: missing={missing}, extra={extra}")
    return len(fixture_paths)


def main() -> int:
    fixture_paths = {
        path.relative_to(ROOT).as_posix() for path in (ROOT / "examples").glob("*-component.json")
    }
    declared_paths = [
        path for path in INTEGRATION_PATHS
        if path.startswith("examples/") and path.endswith("-component.json")
    ]
    catalog = json.loads((ROOT / CATALOG_PATH).read_text(encoding="utf-8"))
    bound_paths = [
        item["path"] for item in catalog["sources"]
        if item["path"].startswith("examples/") and item["path"].endswith("-component.json")
    ]
    count = check_fixture_manifest(
        fixture_paths=fixture_paths,
        declared_paths=declared_paths,
        bound_paths=bound_paths,
    )
    print(f"Specialist fixture manifest matches {count} inert examples")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

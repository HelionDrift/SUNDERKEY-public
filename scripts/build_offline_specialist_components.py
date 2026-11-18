"""Build or check the source-bound catalog for partial offline specialist algorithms."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from sunderkey.offline_specialist_components import (
    CATALOG_PATH,
    MAX_CATALOG_BYTES,
    build_offline_specialist_component_catalog,
    load_offline_specialist_component_catalog,
)

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.check:
        catalog = load_offline_specialist_component_catalog(repository_root=ROOT)
    else:
        catalog = build_offline_specialist_component_catalog(repository_root=ROOT)
        output = ROOT / CATALOG_PATH
        serialized = json.dumps(catalog.to_dict(), indent=2, ensure_ascii=True) + "\n"
        if len(serialized.encode("utf-8")) > MAX_CATALOG_BYTES:
            raise ValueError("Published offline component catalog exceeds its byte limit")
        output.write_text(
            serialized,
            encoding="utf-8",
            newline="\n",
        )
    print(catalog.to_dict()["catalog_id"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

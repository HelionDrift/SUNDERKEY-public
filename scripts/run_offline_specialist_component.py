"""Analyze a supplied local inert JSON fixture without granting runtime resources."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from sunderkey.offline_specialist_components import (
    load_offline_specialist_component_catalog,
    load_offline_specialist_component_request,
    run_offline_specialist_component,
)

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-fixture", type=Path, required=True)
    args = parser.parse_args()
    request = load_offline_specialist_component_request(args.input_fixture)
    catalog = load_offline_specialist_component_catalog(repository_root=ROOT)
    result = run_offline_specialist_component(request, catalog=catalog, repository_root=ROOT)
    print(json.dumps(result, indent=2, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

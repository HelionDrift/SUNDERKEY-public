"""Compose an explicitly supplied inert task fixture without granting runtime resources."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from sunderkey.errors import QualificationError
from sunderkey.offline_specialist_components import load_offline_specialist_component_catalog
from sunderkey.offline_specialist_task import (
    load_offline_specialist_task_model,
    run_offline_specialist_task,
)

ROOT = Path(__file__).resolve().parents[1]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-fixture", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        model = load_offline_specialist_task_model(args.input_fixture)
        catalog = load_offline_specialist_component_catalog(repository_root=ROOT)
        result = run_offline_specialist_task(model, catalog=catalog, repository_root=ROOT)
        output = result.to_json()
    except (OSError, QualificationError) as exc:
        print(f"Validation error: {exc}", file=sys.stderr)
        return 2
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

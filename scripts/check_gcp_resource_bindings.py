"""Read explicit local inputs and validate GCP planning coordinates without cloud access."""

from __future__ import annotations

import argparse
import json
import os
import stat
from pathlib import Path

from sunderkey.deployment_profile_contracts import DeploymentProfile
from sunderkey.gcp_resource_bindings import (
    MAX_PLAN_BYTES,
    GcpResourceBindingError,
    build_gcp_resource_binding_plan,
    parse_gcp_planning_json,
    parse_gcp_source_json,
    verify_gcp_resource_binding_plan,
)
from sunderkey.production_deployment_decision_dossier import ProductionDeploymentDecisionDossier
from sunderkey.regional_custody_contracts import TenantRegionBinding


def read_planning_object(path: Path, *, source: bool = False) -> dict:
    """Read a bounded regular file once, never an environment credential or provider endpoint."""
    try:
        # Nonblocking open prevents a substituted FIFO from hanging before fstat.
        with os.fdopen(os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)), "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_PLAN_BYTES:
                raise GcpResourceBindingError("Input must be a bounded regular file")
            data = stream.read(MAX_PLAN_BYTES + 1)
            after = os.fstat(stream.fileno())
        if len(data) > MAX_PLAN_BYTES or (
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise GcpResourceBindingError("Input exceeded its bound or changed during reading")
        parser = parse_gcp_source_json if source else parse_gcp_planning_json
        return parser(data.decode("utf-8"))
    except (OSError, UnicodeError) as exc:
        raise GcpResourceBindingError("Could not read explicit planning input") from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="Declared coordinate JSON only")
    parser.add_argument("--dossier", type=Path, required=True, help="Exact checked D014 dossier")
    parser.add_argument("--deployment-profile", type=Path, required=True)
    parser.add_argument("--regional-binding", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        sources = {
            "dossier": ProductionDeploymentDecisionDossier.from_dict(
                read_planning_object(args.dossier, source=True)
            ),
            "deployment_profile": DeploymentProfile.from_dict(
                read_planning_object(args.deployment_profile, source=True)
            ),
            "regional_binding": TenantRegionBinding.from_dict(
                read_planning_object(args.regional_binding, source=True)
            ),
        }
        plan = build_gcp_resource_binding_plan(read_planning_object(args.input), **sources)
        result = verify_gcp_resource_binding_plan(plan, **sources)
    except ValueError:
        # Do not print untrusted coordinates, exception content, or potential raw secrets.
        print("GCP planning validation failed: invalid local inputs or source bindings.")
        return 2
    print(json.dumps(result, ensure_ascii=True, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

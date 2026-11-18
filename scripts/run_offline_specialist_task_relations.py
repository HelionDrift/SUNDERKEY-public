"""Print a bounded unsigned dependency analysis over separately supplied inert task inputs."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from sunderkey.errors import QualificationError
from sunderkey.offline_specialist_components import (
    COMPONENTS,
    PROFILE_DEFAULT_COMPONENTS,
    _read_local_regular_file,
    load_offline_specialist_component_catalog,
)
from sunderkey.offline_specialist_task import (
    load_offline_specialist_task_model,
    run_offline_specialist_task,
)
from sunderkey.offline_specialist_task_relations import (
    MAX_MODEL_BYTES,
    OfflineSpecialistTaskRelationsError,
    analyze_offline_specialist_task_relations,
    parse_offline_specialist_task_relations_model,
)

ROOT = Path(__file__).resolve().parents[1]


def _prejoin_original_inputs(plan: dict, task_model: dict) -> None:
    """Reject missing declared jobs/selectors/flow IDs before initial pure calculations."""
    by_job = {job["job_id"]: job["request"] for job in task_model["jobs"]}
    for premise in plan["premises"]:
        request = by_job.get(premise["job_id"])
        if type(request) is not dict:
            raise OfflineSpecialistTaskRelationsError("Premise names an absent original task job")
        profile = request.get("profile_id")
        if type(profile) is not str:
            raise OfflineSpecialistTaskRelationsError(
                "Original profile identity must be native text"
            )
        selected = request.get("component_id", PROFILE_DEFAULT_COMPONENTS.get(profile))
        if type(selected) is not str or selected != premise["component_id"]:
            raise OfflineSpecialistTaskRelationsError(
                "Premise component differs from original selection"
            )
        if not any(row[3] == selected and row[0] == profile for row in COMPONENTS):
            raise OfflineSpecialistTaskRelationsError(
                "Original profile does not own selected component"
            )
        payload = request.get("payload")
        source = payload.get("model") if type(payload) is dict else None
        flows = source.get("flows") if type(source) is dict else None
        if (
            type(flows) is not list
            or sum(
                type(flow) is dict and flow.get("flow_id") == premise["flow_id"] for flow in flows
            )
            != 1
        ):
            raise OfflineSpecialistTaskRelationsError(
                "Premise original flow is absent or ambiguous"
            )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan-fixture", type=Path, required=True)
    parser.add_argument("--task-fixture", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        # Plan shape, references and cycles deny before initial task composition.
        plan = parse_offline_specialist_task_relations_model(
            _read_local_regular_file(args.plan_fixture, MAX_MODEL_BYTES)
        )
        task_model = load_offline_specialist_task_model(args.task_fixture)
        _prejoin_original_inputs(plan, task_model)
        catalog = load_offline_specialist_component_catalog(repository_root=ROOT)
        parent = run_offline_specialist_task(task_model, catalog=catalog, repository_root=ROOT)
        # One initial composition above, one original/current replay inside derivation.
        result = analyze_offline_specialist_task_relations(
            plan,
            task_report=parent,
            task_model=task_model,
            catalog=catalog,
            repository_root=ROOT,
        )
        output = result.to_json()
    except (OSError, QualificationError, OfflineSpecialistTaskRelationsError) as exc:
        print(f"Validation error: {exc}", file=sys.stderr)
        return 2
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

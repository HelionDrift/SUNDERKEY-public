"""Print a bounded unsigned pattern relation over separate inert task fixtures."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from sunderkey import offline_framework_declaration_core as core
from sunderkey import offline_specialist_components as components
from sunderkey import offline_specialist_task as task
from sunderkey.errors import QualificationError
from sunderkey.offline_pattern_task_relations import (
    MAX_PLAN_BYTES,
    MAX_REPORT_BYTES,
    PatternTaskRelationsError,
    analyze_supplied_pattern_task_relations,
    parse_supplied_pattern_task_relations_plan,
    verify_supplied_pattern_task_relations_bytes,
)

ROOT = Path(__file__).resolve().parents[1]


def _prejoin_original_sources(plan: dict, task_model: dict) -> None:
    requests = {row["job_id"]: row["request"] for row in task_model["jobs"]}
    for premise in plan["premises"]:
        request = requests.get(premise["job_id"])
        if type(request) is not dict:
            raise PatternTaskRelationsError("Premise names an absent original task job")
        if (
            request.get("profile_id")
            != {
                "supplied_pickle_opcode_inventory": "AOE-GE-D23-S03",
                "supplied_json_key_policy_differential": "AOE-GE-D23-S04",
                "supplied_archive_member_paths": "AOE-GE-D23-S05",
                "supplied_dns_scope_timeline": "AOE-GE-D23-S06",
                "supplied_cross_surface_authorization": "AOE-GE-D23-S07",
                "supplied_cross_channel_session": "AOE-GE-D23-S08",
                "supplied_request_origin_trust": "AOE-GE-D23-S09",
                "supplied_toctou_state_schedule": "AOE-GE-D23-S10",
                "supplied_resource_expansion_budget": "AOE-GE-D23-S11",
                "supplied_dependency_fail_closed": "AOE-GE-D23-S12",
                "supplied_configuration_defaults": "AOE-GE-D23-S13",
                "supplied_confused_deputy_boundary": "AOE-GE-D23-S14",
                "supplied_integrity_poisoning": "AOE-GE-D23-S15",
                "supplied_query_input_boundary": "AOE-GE-D23-S01",
                "supplied_interpreter_input_boundary": "AOE-GE-D23-S02",
                "supplied_observable_discrepancy": "AOE-GE-D23-S16",
            }[premise["component_id"]]
            or request.get("component_id") != premise["component_id"]
        ):
            raise PatternTaskRelationsError("Premise component differs from original selection")
        payload = request.get("payload")
        source = payload.get("model") if type(payload) is dict else None
        if type(source) is not dict:
            raise PatternTaskRelationsError("Premise original source is absent")
        source_sha256 = core.digest(core.canonical(source).encode("ascii"))
        if source_sha256 != premise["source_model_sha256"]:
            raise PatternTaskRelationsError("Premise original source digest differs")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan-fixture", type=Path, required=True)
    parser.add_argument("--task-fixture", type=Path, required=True)
    parser.add_argument("--verify-report-fixture", type=Path)
    args = parser.parse_args(argv)
    try:
        plan = parse_supplied_pattern_task_relations_plan(
            components._read_local_regular_file(args.plan_fixture, MAX_PLAN_BYTES)
        )
        task_model = task.load_offline_specialist_task_model(args.task_fixture)
        _prejoin_original_sources(plan, task_model)
        report_bytes = (
            components._read_local_regular_file(args.verify_report_fixture, MAX_REPORT_BYTES)
            if args.verify_report_fixture is not None else None
        )
        catalog = components.load_offline_specialist_component_catalog(repository_root=ROOT)
        original = task.run_offline_specialist_task(
            task_model, catalog=catalog, repository_root=ROOT
        )
        if report_bytes is None:
            result = analyze_supplied_pattern_task_relations(
                plan, task_report=original, task_model=task_model,
                catalog=catalog, repository_root=ROOT,
            )
        else:
            result = verify_supplied_pattern_task_relations_bytes(
                report_bytes, model=plan, task_report=original,
                task_model=task_model, catalog=catalog, repository_root=ROOT,
            )
        output = result.to_json()
    except (
        OSError,
        QualificationError,
        components.OfflineSpecialistComponentError,
        PatternTaskRelationsError,
    ) as exc:
        print(f"Validation error: {exc}", file=sys.stderr)
        return 2
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

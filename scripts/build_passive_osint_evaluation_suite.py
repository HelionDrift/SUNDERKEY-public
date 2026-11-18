"""Build the advisory Passive OSINT qualification evaluation suite."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

PROFILE_ID = "AOE-GA-D01-S01"
CANDIDATE_ID = "development.passive-osint"
CANDIDATE_VERSION = "1.0.0"
SUITE_ID = "development.passive-osint.qualification"
SUITE_VERSION = "1.0.0"
SCENARIO_DOMAIN = "sunderkey.qualification-scenario-source.v1"
EXPECTED_DOMAIN = "sunderkey.qualification-expected-result.v1"
CRITICAL_FAILURE_DOMAIN = "sunderkey.qualification-critical-failure.v1"


def build_parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[1]
    registry = root / "registry"
    source = root / "examples" / "implementation" / "passive-osint"
    parser = argparse.ArgumentParser(
        description="Build the advisory Passive OSINT qualification suite"
    )
    parser.add_argument("--registry", default=str(registry / "army-v1.json"))
    parser.add_argument(
        "--capabilities",
        default=str(registry / "capabilities-army-v1.json"),
    )
    parser.add_argument(
        "--standard",
        default=str(registry / "qualification-standard-v1.json"),
    )
    parser.add_argument(
        "--plans",
        default=str(registry / "qualification-plans-army-v1.json"),
    )
    parser.add_argument(
        "--candidates",
        default=str(source / "candidate-implementations-v1.json"),
    )
    parser.add_argument(
        "--scenarios",
        default=str(source / "evaluation-scenarios-v1.json"),
    )
    parser.add_argument(
        "--output",
        default=str(source / "evaluation-suite-v1.json"),
    )
    return parser


def _read_json(path: str) -> dict[str, Any]:
    resolved = Path(path).resolve()
    value = json.loads(resolved.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"Expected a JSON object: {resolved}")
    return value


def _canonical_sha256(value: Any) -> str:
    payload = json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def _require_exact_fields(
    value: dict[str, Any],
    fields: set[str],
    label: str,
) -> None:
    if set(value) != fields:
        raise ValueError(f"{label} fields do not match the source contract")


def _find_one(items: Any, key: str, expected: str, label: str) -> dict[str, Any]:
    if not isinstance(items, list):
        raise ValueError(f"{label} collection must be a list")
    matches = [item for item in items if isinstance(item, dict) and item.get(key) == expected]
    if len(matches) != 1:
        raise ValueError(f"Expected exactly one {label} for {expected}")
    return matches[0]


def _validate_candidate(
    candidates: dict[str, Any],
    source_candidate: dict[str, Any],
) -> dict[str, Any]:
    _require_exact_fields(
        source_candidate,
        {"candidate_id", "candidate_version", "candidate_artifact_sha256"},
        "scenario candidate",
    )
    candidate = _find_one(
        candidates.get("candidates"),
        "candidate_id",
        CANDIDATE_ID,
        "candidate",
    )
    expected = {
        "candidate_id": CANDIDATE_ID,
        "candidate_version": CANDIDATE_VERSION,
        "candidate_artifact_sha256": candidate.get("candidate_artifact_sha256"),
    }
    if source_candidate != expected or candidate.get("profile_id") != PROFILE_ID:
        raise ValueError("Scenario candidate binding is invalid")
    if candidate.get("lifecycle") != "development":
        raise ValueError("Passive OSINT candidate must remain in development")
    return expected


def _validate_cases(
    cases: Any,
    standard: dict[str, Any],
    required_gate_ids: list[str],
) -> list[dict[str, Any]]:
    if not isinstance(cases, list) or not cases:
        raise ValueError("Scenario source must define cases")
    gate_requirements = {gate["id"]: gate["minimum_scenarios"] for gate in standard["gates"]}
    if set(required_gate_ids) != set(gate_requirements):
        raise ValueError("Passive OSINT plan must require every standard gate")
    fields = {
        "case_id",
        "gate_id",
        "ordinal",
        "environment",
        "title",
        "input",
        "expected_behaviors",
        "prohibited_behaviors",
        "critical_failure",
    }
    case_ids: set[str] = set()
    by_gate: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for index, case in enumerate(cases):
        if not isinstance(case, dict):
            raise ValueError(f"Scenario case {index} must be an object")
        _require_exact_fields(case, fields, f"scenario case {index}")
        case_id = case.get("case_id")
        gate_id = case.get("gate_id")
        if not isinstance(case_id, str) or not case_id.startswith("QCASE-"):
            raise ValueError(f"Scenario case {index} ID is invalid")
        if case_id in case_ids:
            raise ValueError("Scenario case IDs must be unique")
        case_ids.add(case_id)
        if gate_id not in gate_requirements:
            raise ValueError(f"Scenario case {case_id} uses an unknown gate")
        if case.get("environment") != "synthetic":
            raise ValueError(f"Scenario case {case_id} must be synthetic")
        if not isinstance(case.get("title"), str) or not case["title"].strip():
            raise ValueError(f"Scenario case {case_id} requires a title")
        if not isinstance(case.get("input"), str) or not case["input"].strip():
            raise ValueError(f"Scenario case {case_id} requires an input")
        for field in ("expected_behaviors", "prohibited_behaviors"):
            values = case.get(field)
            if (
                not isinstance(values, list)
                or not values
                or not all(isinstance(item, str) and item.strip() for item in values)
            ):
                raise ValueError(f"Scenario case {case_id} requires {field}")
        if (
            not isinstance(case.get("critical_failure"), str)
            or not case["critical_failure"].strip()
        ):
            raise ValueError(f"Scenario case {case_id} requires a critical failure")
        by_gate[gate_id].append(case)
    for gate_id, minimum in gate_requirements.items():
        gate_cases = sorted(by_gate[gate_id], key=lambda item: item["ordinal"])
        if len(gate_cases) != minimum:
            raise ValueError(f"Scenario count for {gate_id} must equal {minimum}")
        if [item["ordinal"] for item in gate_cases] != list(range(1, minimum + 1)):
            raise ValueError(f"Scenario ordinals for {gate_id} must be contiguous")
    return sorted(cases, key=lambda item: (item["gate_id"], item["ordinal"]))


def build_suite(
    registry: dict[str, Any],
    capabilities: dict[str, Any],
    standard: dict[str, Any],
    plans: dict[str, Any],
    candidates: dict[str, Any],
    scenarios: dict[str, Any],
) -> dict[str, Any]:
    _require_exact_fields(
        scenarios,
        {
            "schema_version",
            "pack_id",
            "pack_version",
            "profile_id",
            "candidate",
            "suite_mode",
            "advisory_only",
            "observation_status",
            "cases",
        },
        "scenario source",
    )
    if (
        scenarios.get("schema_version") != 1
        or scenarios.get("profile_id") != PROFILE_ID
        or scenarios.get("suite_mode") != "synthetic"
        or scenarios.get("advisory_only") is not True
        or scenarios.get("observation_status") != "not_run"
    ):
        raise ValueError("Scenario source safety binding is invalid")
    profile = _find_one(registry.get("profiles"), "id", PROFILE_ID, "profile")
    if profile.get("kind") != "specialist":
        raise ValueError("Passive OSINT profile must be a specialist")
    plan = _find_one(
        plans.get("profile_plans"),
        "profile_id",
        PROFILE_ID,
        "qualification plan",
    )
    candidate_binding = _validate_candidate(candidates, scenarios["candidate"])
    cases = _validate_cases(
        scenarios["cases"],
        standard,
        plan["required_gate_ids"],
    )
    derived_cases = []
    for case in cases:
        expected = {
            "case_id": case["case_id"],
            "expected_behaviors": case["expected_behaviors"],
            "prohibited_behaviors": case["prohibited_behaviors"],
        }
        critical_failure = {
            "case_id": case["case_id"],
            "definition": case["critical_failure"],
        }
        derived_cases.append(
            {
                "case_id": case["case_id"],
                "gate_id": case["gate_id"],
                "ordinal": case["ordinal"],
                "environment": case["environment"],
                "scenario_sha256": _canonical_sha256({"domain": SCENARIO_DOMAIN, "scenario": case}),
                "expected_result_sha256": _canonical_sha256(
                    {"domain": EXPECTED_DOMAIN, "expected_result": expected}
                ),
                "critical_failure_definition_sha256": _canonical_sha256(
                    {
                        "domain": CRITICAL_FAILURE_DOMAIN,
                        "critical_failure": critical_failure,
                    }
                ),
            }
        )
    return {
        "schema_version": 1,
        "suite_id": SUITE_ID,
        "suite_version": SUITE_VERSION,
        "suite_mode": "synthetic",
        "advisory_only": True,
        "expert_catalog_id": registry["catalog_id"],
        "expert_catalog_version": registry["catalog_version"],
        "capability_catalog_id": capabilities["catalog_id"],
        "capability_catalog_version": capabilities["catalog_version"],
        "capability_catalog_sha256": _canonical_sha256(capabilities),
        "qualification_standard_id": standard["standard_id"],
        "qualification_standard_version": standard["standard_version"],
        "qualification_standard_sha256": _canonical_sha256(standard),
        "qualification_plan_catalog_id": plans["plan_catalog_id"],
        "qualification_plan_catalog_version": plans["plan_catalog_version"],
        "qualification_plan_catalog_sha256": _canonical_sha256(plans),
        "profile_id": PROFILE_ID,
        "scenario_family_id": plan["scenario_family_id"],
        "candidate": candidate_binding,
        "cases": derived_cases,
    }


def build_report(args: argparse.Namespace) -> dict[str, Any]:
    return build_suite(
        _read_json(args.registry),
        _read_json(args.capabilities),
        _read_json(args.standard),
        _read_json(args.plans),
        _read_json(args.candidates),
        _read_json(args.scenarios),
    )


def _write_json(path: str, value: dict[str, Any]) -> Path:
    output = Path(path).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(value, ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return output


def main() -> None:
    args = build_parser().parse_args()
    suite = build_report(args)
    output = _write_json(args.output, suite)
    print(f"Wrote {len(suite['cases'])} evaluation cases: {output}")


if __name__ == "__main__":
    main()

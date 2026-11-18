"""Build the deterministic advisory qualification contract fixture."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

PROFILE_ID = "AOE-GA-D01-S01"
CANDIDATE_ID = "fixture.passive-osint"
CANDIDATE_VERSION = "1.0.0"


def build_parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(
        description="Build the advisory qualification contract fixture"
    )
    parser.add_argument(
        "--registry",
        default=str(root / "registry" / "army-v1.json"),
    )
    parser.add_argument(
        "--capabilities",
        default=str(root / "registry" / "capabilities-army-v1.json"),
    )
    parser.add_argument(
        "--standard",
        default=str(root / "registry" / "qualification-standard-v1.json"),
    )
    parser.add_argument(
        "--plans",
        default=str(
            root / "registry" / "qualification-plans-army-v1.json"
        ),
    )
    parser.add_argument(
        "--candidates",
        default=str(
            root / "registry" / "candidate-implementations-v1.json"
        ),
    )
    parser.add_argument(
        "--suite-output",
        default=str(
            root
            / "examples"
            / "qualification"
            / "passive-osint-suite.json"
        ),
    )
    parser.add_argument(
        "--observations-output",
        default=str(
            root
            / "examples"
            / "qualification"
            / "passive-osint-observations.json"
        ),
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


def build_fixture(
    registry: dict[str, Any],
    capabilities: dict[str, Any],
    standard: dict[str, Any],
    plans: dict[str, Any],
    candidates: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    plan = next(
        item
        for item in plans["profile_plans"]
        if item["profile_id"] == PROFILE_ID
    )
    catalog_candidate = next(
        item
        for item in candidates["candidates"]
        if item["candidate_id"] == CANDIDATE_ID
        and item["candidate_version"] == CANDIDATE_VERSION
    )
    if catalog_candidate["profile_id"] != PROFILE_ID:
        raise ValueError("Candidate profile binding changed")
    candidate = {
        "candidate_id": catalog_candidate["candidate_id"],
        "candidate_version": catalog_candidate["candidate_version"],
        "candidate_artifact_sha256": catalog_candidate[
            "candidate_artifact_sha256"
        ],
    }
    cases: list[dict[str, Any]] = []
    for gate in sorted(standard["gates"], key=lambda item: item["id"]):
        gate_id = str(gate["id"])
        gate_slug = gate_id.removeprefix("qualification.gate.").upper()
        for ordinal in range(1, int(gate["minimum_scenarios"]) + 1):
            case_id = f"QCASE-{PROFILE_ID}-{gate_slug}-{ordinal:02d}"
            case_identity = {
                "fixture": "qualification-scenario",
                "profile_id": PROFILE_ID,
                "gate_id": gate_id,
                "ordinal": ordinal,
            }
            cases.append(
                {
                    "case_id": case_id,
                    "gate_id": gate_id,
                    "ordinal": ordinal,
                    "environment": "synthetic",
                    "scenario_sha256": _canonical_sha256(case_identity),
                    "expected_result_sha256": _canonical_sha256(
                        {
                            **case_identity,
                            "contract": "expected-result",
                        }
                    ),
                    "critical_failure_definition_sha256": (
                        _canonical_sha256(
                            {
                                "gate_id": gate_id,
                                "contract": "critical-failure-definition",
                                "maximum": gate[
                                    "maximum_critical_failures"
                                ],
                            }
                        )
                    ),
                }
            )
    suite = {
        "schema_version": 1,
        "suite_id": "fixture.passive-osint.qualification",
        "suite_version": "1.0.0",
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
        "qualification_plan_catalog_version": plans[
            "plan_catalog_version"
        ],
        "qualification_plan_catalog_sha256": _canonical_sha256(plans),
        "profile_id": PROFILE_ID,
        "scenario_family_id": plan["scenario_family_id"],
        "candidate": candidate,
        "cases": cases,
    }
    observations = {
        "schema_version": 1,
        "observation_set_id": "fixture.passive-osint.observations",
        "observation_set_version": "1.0.0",
        "advisory_only": True,
        "suite_id": suite["suite_id"],
        "suite_version": suite["suite_version"],
        "suite_sha256": _canonical_sha256(suite),
        "profile_id": PROFILE_ID,
        "candidate": candidate,
        "observations": [
            {
                "case_id": case["case_id"],
                "outcome": "pass",
                "critical_failure": False,
                "result_sha256": _canonical_sha256(
                    {
                        "fixture": "qualification-result",
                        "case_id": case["case_id"],
                        "outcome": "pass",
                    }
                ),
                "evidence_manifest_sha256": _canonical_sha256(
                    {
                        "fixture": "evidence-manifest",
                        "case_id": case["case_id"],
                    }
                ),
            }
            for case in cases
        ],
    }
    return suite, observations


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
    suite, observations = build_fixture(
        _read_json(args.registry),
        _read_json(args.capabilities),
        _read_json(args.standard),
        _read_json(args.plans),
        _read_json(args.candidates),
    )
    suite_output = _write_json(args.suite_output, suite)
    observations_output = _write_json(
        args.observations_output,
        observations,
    )
    print(f"Wrote {len(suite['cases'])} cases: {suite_output}")
    print(f"Wrote observations: {observations_output}")


if __name__ == "__main__":
    main()

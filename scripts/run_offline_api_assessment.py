"""Run or verify the native API correlation over a bounded synthetic JSON case.

This command reads local fixture data only. It does not contact a target,
authorize execution, publish a finding, or claim evidence provenance.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from scripts.build_candidate_adapter_catalog import load_blueprints
from sunderkey.candidate_adapter_sdk import AdapterInvocation, load_candidate_adapter_catalog
from sunderkey.candidate_implementation_strategy import load_candidate_implementation_strategy
from sunderkey.errors import QualificationError
from sunderkey.finding_validators import EvidenceRecord, FindingValidationError
from sunderkey.offline_api_assessment import (
    OfflineApiAssessmentError,
    OfflineApiCaseSource,
    build_offline_api_batch,
    compare_offline_api_retest,
    evaluate_offline_api_case,
    verify_offline_api_batch,
    verify_offline_api_case,
    verify_offline_api_retest,
)
from sunderkey.reference_adapters import build_reference_adapters
from sunderkey.validation import loads_json_without_duplicate_keys

ROOT = Path(__file__).resolve().parents[1]
MAX_CASE_BYTES = 262_144
MAX_RESULT_BYTES = 16_384
CASE_FIELDS = {
    "schema_version",
    "case_id",
    "invocation_id",
    "mission_id",
    "target_id",
    "scope_id",
    "responses",
}
RESPONSE_FIELDS = {
    "evidence_id",
    "principal_id",
    "object_id",
    "action",
    "expected_access",
    "status_code",
    "body",
}


class OfflineApiCommandError(ValueError):
    """Raised when a local synthetic case or result cannot be processed."""


def _read_json(path: Path, maximum_bytes: int) -> Any:
    try:
        with path.open("rb") as source:
            encoded = source.read(maximum_bytes + 1)
        if len(encoded) > maximum_bytes:
            raise OfflineApiCommandError("input exceeds its byte limit")
        return loads_json_without_duplicate_keys(encoded.decode("utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        if isinstance(exc, OfflineApiCommandError):
            raise
        raise OfflineApiCommandError("could not read bounded JSON input") from exc


def _native_adapter():
    registry = ROOT / "registry"
    strategy = load_candidate_implementation_strategy(
        registry / "candidate-implementation-strategy-v1.json"
    )
    catalog = load_candidate_adapter_catalog(
        registry / "candidate-adapters-reference-v1.json",
        strategy,
        load_blueprints(),
        ROOT,
    )
    return build_reference_adapters(catalog)["AOE-GB-D06-S09"]


def _prepare_case(
    raw: Any, adapter: Any
) -> tuple[str, AdapterInvocation, tuple[EvidenceRecord, ...]]:
    if (
        not isinstance(raw, dict)
        or set(raw) != CASE_FIELDS
        or type(raw.get("schema_version")) is not int
        or raw["schema_version"] != 1
    ):
        raise OfflineApiCommandError("synthetic case fields are invalid")
    responses = raw["responses"]
    if not isinstance(responses, list) or not 1 <= len(responses) <= 64:
        raise OfflineApiCommandError("one to 64 synthetic responses are required")
    records: list[EvidenceRecord] = []
    for item in responses:
        if not isinstance(item, dict) or set(item) != RESPONSE_FIELDS:
            raise OfflineApiCommandError("synthetic response fields are invalid")
        if not isinstance(item["body"], (dict, list)):
            raise OfflineApiCommandError("synthetic response body must be a JSON object or array")
        try:
            body = json.dumps(
                item["body"],
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("ascii")
        except ValueError as exc:
            raise OfflineApiCommandError("synthetic response body is not valid JSON") from exc
        records.append(
            EvidenceRecord.from_bytes(
                item["evidence_id"],
                body,
                role="response",
                status_code=item["status_code"],
                media_type="application/json",
                attributes={
                    "principal_id": item["principal_id"],
                    "object_id": item["object_id"],
                    "action": item["action"],
                    "expected_access": item["expected_access"],
                },
            )
        )
    ordered = tuple(sorted(records, key=lambda record: record.evidence_id))
    invocation = AdapterInvocation(
        invocation_id=raw["invocation_id"],
        mission_id=raw["mission_id"],
        authority_ref="AUTH-SYNTHETIC-NONQUALIFYING",
        profile_id=adapter.manifest.profile_id,
        vector_id=adapter.manifest.vector_id,
        target_id=raw["target_id"],
        scope_id=raw["scope_id"],
        action_tier="R0",
        environment="synthetic",
        dry_run=True,
        credential_refs=(),
        input_data={
            "exchanges": [
                {
                    "evidence_id": record.evidence_id,
                    "subject_id": record.attributes["principal_id"],
                    "object_id": record.attributes["object_id"],
                    "expected_permitted": record.attributes["expected_access"],
                    "status_code": record.status_code,
                }
                for record in ordered
            ]
        },
    )
    return raw["case_id"], invocation, ordered


def run_case(raw: Any) -> dict[str, Any]:
    adapter = _native_adapter()
    case_id, invocation, evidence = _prepare_case(raw, adapter)
    return evaluate_offline_api_case(
        adapter=adapter, case_id=case_id, invocation=invocation, evidence=evidence
    ).to_dict()


def verify_case(raw: Any, result: Any) -> dict[str, Any]:
    adapter = _native_adapter()
    case_id, invocation, evidence = _prepare_case(raw, adapter)
    checked = verify_offline_api_case(
        adapter=adapter,
        case_id=case_id,
        invocation=invocation,
        evidence=evidence,
        result=result,
    )
    return {
        "status": "valid",
        "result_sha256": checked.result_sha256,
        "qualification_effect": "none",
    }


def compare_cases(
    prior_raw: Any,
    prior_result: Any,
    second_raw: Any,
    second_result: Any,
) -> dict[str, Any]:
    adapter = _native_adapter()
    prior_case_id, prior_invocation, prior_evidence = _prepare_case(prior_raw, adapter)
    second_case_id, second_invocation, second_evidence = _prepare_case(second_raw, adapter)
    return compare_offline_api_retest(
        adapter=adapter,
        prior_case_id=prior_case_id,
        prior_invocation=prior_invocation,
        prior_evidence=prior_evidence,
        prior_result=prior_result,
        second_case_id=second_case_id,
        second_invocation=second_invocation,
        second_evidence=second_evidence,
        second_result=second_result,
    ).to_dict()


def verify_comparison(
    prior_raw: Any,
    prior_result: Any,
    second_raw: Any,
    second_result: Any,
    comparison: Any,
) -> dict[str, Any]:
    adapter = _native_adapter()
    prior_case_id, prior_invocation, prior_evidence = _prepare_case(prior_raw, adapter)
    second_case_id, second_invocation, second_evidence = _prepare_case(second_raw, adapter)
    checked = verify_offline_api_retest(
        result=comparison,
        adapter=adapter,
        prior_case_id=prior_case_id,
        prior_invocation=prior_invocation,
        prior_evidence=prior_evidence,
        prior_result=prior_result,
        second_case_id=second_case_id,
        second_invocation=second_invocation,
        second_evidence=second_evidence,
        second_result=second_result,
    )
    return {
        "status": "valid",
        "result_sha256": checked.result_sha256,
        "qualification_effect": "none",
    }


def _batch_sources(pairs: list[tuple[Any, Any]], adapter: Any) -> tuple[OfflineApiCaseSource, ...]:
    if not 1 <= len(pairs) <= 64:
        raise OfflineApiCommandError("one to 64 case and result pairs are required")
    sources: list[OfflineApiCaseSource] = []
    for raw, result in pairs:
        case_id, invocation, evidence = _prepare_case(raw, adapter)
        sources.append(OfflineApiCaseSource(case_id, invocation, evidence, result))
    return tuple(sources)


def run_batch(pairs: list[tuple[Any, Any]]) -> dict[str, Any]:
    adapter = _native_adapter()
    return build_offline_api_batch(
        adapter=adapter, sources=_batch_sources(pairs, adapter)
    ).to_dict()


def verify_batch(pairs: list[tuple[Any, Any]], batch: Any) -> dict[str, Any]:
    adapter = _native_adapter()
    checked = verify_offline_api_batch(
        adapter=adapter, sources=_batch_sources(pairs, adapter), batch=batch
    )
    return {
        "status": "valid",
        "batch_sha256": checked.batch_sha256,
        "qualification_effect": "none",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    run_parser = subparsers.add_parser("run", help="evaluate a local synthetic case")
    run_parser.add_argument("--input", required=True)
    verify_parser = subparsers.add_parser("verify", help="reproduce a local synthetic result")
    verify_parser.add_argument("--input", required=True)
    verify_parser.add_argument("--result", required=True)
    retest_parser = subparsers.add_parser("retest", help="compare two reproduced synthetic cases")
    retest_verify_parser = subparsers.add_parser(
        "retest-verify", help="reproduce and verify a synthetic comparison"
    )
    for selected in (retest_parser, retest_verify_parser):
        selected.add_argument("--prior-input", required=True)
        selected.add_argument("--prior-result", required=True)
        selected.add_argument("--second-input", required=True)
        selected.add_argument("--second-result", required=True)
    retest_verify_parser.add_argument("--comparison", required=True)
    batch_parser = subparsers.add_parser("batch", help="roll up reproduced synthetic cases")
    batch_verify_parser = subparsers.add_parser(
        "batch-verify", help="reproduce and verify a synthetic case rollup"
    )
    for selected in (batch_parser, batch_verify_parser):
        selected.add_argument(
            "--case",
            nargs=2,
            action="append",
            required=True,
            metavar=("INPUT", "RESULT"),
        )
    batch_verify_parser.add_argument("--batch-result", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command in {"run", "verify"}:
            case = _read_json(Path(args.input), MAX_CASE_BYTES)
            if args.command == "run":
                output = run_case(case)
            else:
                result = _read_json(Path(args.result), MAX_RESULT_BYTES)
                output = verify_case(case, result)
        elif args.command in {"retest", "retest-verify"}:
            prior_case = _read_json(Path(args.prior_input), MAX_CASE_BYTES)
            prior_result = _read_json(Path(args.prior_result), MAX_RESULT_BYTES)
            second_case = _read_json(Path(args.second_input), MAX_CASE_BYTES)
            second_result = _read_json(Path(args.second_result), MAX_RESULT_BYTES)
            if args.command == "retest":
                output = compare_cases(prior_case, prior_result, second_case, second_result)
            else:
                comparison = _read_json(Path(args.comparison), MAX_RESULT_BYTES)
                output = verify_comparison(
                    prior_case, prior_result, second_case, second_result, comparison
                )
        else:
            if not 1 <= len(args.case) <= 64:
                raise OfflineApiCommandError("one to 64 case and result pairs are required")
            pairs = [
                (
                    _read_json(Path(case_path), MAX_CASE_BYTES),
                    _read_json(Path(result_path), MAX_RESULT_BYTES),
                )
                for case_path, result_path in args.case
            ]
            if args.command == "batch":
                output = run_batch(pairs)
            else:
                batch = _read_json(Path(args.batch_result), MAX_RESULT_BYTES)
                output = verify_batch(pairs, batch)
    except (
        OfflineApiCommandError,
        OfflineApiAssessmentError,
        FindingValidationError,
        QualificationError,
    ) as exc:
        print(f"Validation error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(output, ensure_ascii=True, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

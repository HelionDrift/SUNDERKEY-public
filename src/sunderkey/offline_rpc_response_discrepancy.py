"""Compare supplied RPC response digests for one declared finalized query."""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from . import offline_framework_declaration_core as core

COMPONENT_ID = "rpc_supplied_cross_endpoint_response_discrepancy"
PROFILE_ID = "AOE-GB-D10-S12"
CAPABILITY_ID = "army.gb.d10.s12"
VECTOR_ID = "AV-GB-D10-S12-01"
WORK_PACKAGE_ID = "IWP2-AOE-GB-D10-S12"
WAVE_ID = "IW2-012"
COMMANDER_ID = "AOE-GB-D10-CMD"
INDEPENDENT_VALIDATOR_ID = "AOE-HQ-19"
BLUEPRINT_SHA256 = "sha256:946b6a2900d4c7e95cb78efc7fb946fbae77bcd2c4d23c7d60bae474d93c3fc3"
DOMAIN = "sunderkey.offline-rpc-response-discrepancy.v1"
MAX_MODEL_BYTES = 65_536
MAX_REPORT_BYTES = 131_072
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
EFFECTS = {
    key: "none"
    for key in (
        "authority",
        "execution",
        "filesystem",
        "network",
        "process",
        "provider",
        "credentials",
        "target_interaction",
        "finding_publication",
        "qualification",
    )
}


class RpcResponseDiscrepancyError(ValueError):
    """A supplied RPC observation set or original-model replay is invalid."""


def _model(value: Any) -> tuple[dict, str]:
    core.validate_tree(value, maximum=MAX_MODEL_BYTES)
    model = core.exact(
        json.loads(core.canonical(value)),
        {"schema_version", "source_id", "context_complete", "observations"},
        "model",
    )
    if type(model["schema_version"]) is not int or model["schema_version"] != 1:
        raise RpcResponseDiscrepancyError("Unsupported model version")
    core.identifier(model["source_id"], "source ID")
    core.boolean(model["context_complete"], "context completeness")
    observations = core.bounded_list(model["observations"], 64, "observations")
    if not observations:
        raise RpcResponseDiscrepancyError("At least one observation is required")
    seen: set[str] = set()
    for item in observations:
        row = core.exact(
            item,
            {
                "observation_id",
                "chain_id",
                "block_ref",
                "block_finalized",
                "method_id",
                "params_sha256",
                "result_sha256",
                "endpoint_id",
            },
            "observation",
        )
        observation_id = core.identifier(row["observation_id"], "observation ID")
        if observation_id in seen:
            raise RpcResponseDiscrepancyError("Duplicate observation ID")
        seen.add(observation_id)
        for key in ("chain_id", "block_ref", "method_id", "endpoint_id"):
            core.identifier(row[key], key)
        core.boolean(row["block_finalized"], "block finality")
        for key in ("params_sha256", "result_sha256"):
            digest = row[key]
            if type(digest) is not str or _DIGEST.fullmatch(digest) is None:
                raise RpcResponseDiscrepancyError(
                    "Query and result digests must be lowercase SHA-256"
                )
    return model, core.canonical(model)


def _derive(value: Any) -> dict:
    model, model_text = _model(value)
    grouped: dict[tuple[str, str, str, str], list[dict]] = defaultdict(list)
    for row in model["observations"]:
        key = (row["chain_id"], row["block_ref"], row["method_id"], row["params_sha256"])
        grouped[key].append(row)
    projections = []
    for key, rows in sorted(grouped.items()):
        by_result: dict[str, set[str]] = defaultdict(set)
        for row in rows:
            by_result[row["result_sha256"]].add(row["endpoint_id"])
        divergent = any(
            first != second
            and any(
                first_endpoint != second_endpoint
                for first_endpoint in first_endpoints
                for second_endpoint in second_endpoints
            )
            for first, first_endpoints in by_result.items()
            for second, second_endpoints in by_result.items()
        )
        disposition = (
            "unknown"
            if not model["context_complete"] or not all(row["block_finalized"] for row in rows)
            else "candidate_declared_cross_endpoint_rpc_discrepancy"
            if divergent
            else "no_declared_cross_endpoint_rpc_discrepancy"
        )
        projections.append(
            {
                "chain_id": key[0],
                "block_ref": key[1],
                "method_id": key[2],
                "params_sha256": key[3],
                "result_groups": [
                    {"result_sha256": digest, "endpoint_ids": sorted(endpoints)}
                    for digest, endpoints in sorted(by_result.items())
                ],
                "disposition": disposition,
            }
        )
    body = {
        "schema_version": 1,
        "component_id": COMPONENT_ID,
        "profile_id": PROFILE_ID,
        "work_package_id": WORK_PACKAGE_ID,
        "blueprint_sha256": BLUEPRINT_SHA256,
        "source_model_sha256": core.digest(model_text.encode("ascii")),
        "observation_count": len(model["observations"]),
        "query_projections": projections,
        "candidate_count": sum(row["disposition"].startswith("candidate_") for row in projections),
        "unknown_count": sum(row["disposition"] == "unknown" for row in projections),
        "source_authenticated": False,
        "endpoints_queried": False,
        "finality_verified": False,
        "response_canonicalization_verified": False,
        "finding_claimed": False,
        "full_candidate_assembled": False,
        "positive_use_approved": False,
        "qualification_claimed": False,
        "operational_effects": dict(EFFECTS),
        "limitations": [
            "Endpoint, block, query and response identities are caller-supplied.",
            "No RPC request, finality proof or response canonicalization is performed.",
            "Different digests do not prove an inconsistent ledger or malicious node.",
        ],
    }
    report_id, report_sha256 = core.report_address(body, domain=DOMAIN, prefix="RRD-")
    result = {**body, "report_id": report_id, "report_sha256": report_sha256}
    core.validate_tree(result, maximum=MAX_REPORT_BYTES)
    return result


@dataclass(frozen=True, slots=True, init=False)
class RpcResponseDiscrepancyReport:
    """Unsigned endpoint comparison requiring original-model replay."""

    _document_json: str

    def __init__(self, _document: Any = None) -> None:
        raise RpcResponseDiscrepancyError("Use analysis or original-model replay")

    @classmethod
    def _owned(cls, document: dict) -> RpcResponseDiscrepancyReport:
        result = object.__new__(cls)
        object.__setattr__(result, "_document_json", core.canonical(document))
        return result

    def to_dict(self) -> dict:
        return json.loads(self._document_json)

    def to_json(self) -> str:
        return self._document_json


def analyze_supplied_rpc_responses(model: Any) -> RpcResponseDiscrepancyReport:
    return RpcResponseDiscrepancyReport._owned(_derive(model))


def verify_supplied_rpc_responses(report: Any, *, model: Any) -> RpcResponseDiscrepancyReport:
    if type(report) is not RpcResponseDiscrepancyReport:
        raise RpcResponseDiscrepancyError("Exact RPC-discrepancy wrapper required")
    expected = _derive(model)
    if report.to_json() != core.canonical(expected):
        raise RpcResponseDiscrepancyError("Report differs from separate original model")
    return RpcResponseDiscrepancyReport._owned(expected)


def verify_supplied_rpc_responses_bytes(
    report_bytes: bytes, *, model: Any
) -> RpcResponseDiscrepancyReport:
    report = core.decode(report_bytes, maximum=MAX_REPORT_BYTES)
    if type(report) is not dict:
        raise RpcResponseDiscrepancyError("Exported report must be an object")
    expected = _derive(model)
    if core.canonical(report) != core.canonical(expected):
        raise RpcResponseDiscrepancyError("Exported report differs from original replay")
    return RpcResponseDiscrepancyReport._owned(expected)


def component_fixture() -> dict:
    return {
        "schema_version": 1,
        "source_id": "synthetic-rpc-observations",
        "context_complete": True,
        "observations": [
            {
                "observation_id": "observation-one",
                "chain_id": "chain-a",
                "block_ref": "finalized-height-10",
                "block_finalized": True,
                "method_id": "read-state",
                "params_sha256": "sha256:" + "1" * 64,
                "result_sha256": "sha256:" + "2" * 64,
                "endpoint_id": "node-a",
            },
            {
                "observation_id": "observation-two",
                "chain_id": "chain-a",
                "block_ref": "finalized-height-10",
                "block_finalized": True,
                "method_id": "read-state",
                "params_sha256": "sha256:" + "1" * 64,
                "result_sha256": "sha256:" + "3" * 64,
                "endpoint_id": "node-b",
            },
        ],
    }

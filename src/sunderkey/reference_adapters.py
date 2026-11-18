"""Offline synthetic reference adapters for the first Phase 157 slice."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from .candidate_adapter_sdk import (
    AdapterEvidence,
    AdapterInvocation,
    AdapterManifest,
    AdapterResult,
    CandidateAdapterCatalog,
    validate_reference_invocation,
)
from .errors import QualificationError
from .qualification import _canonical_json


def _list_of_mappings(value: Any, label: str) -> list[Mapping[str, Any]]:
    if not isinstance(value, list) or any(not isinstance(item, Mapping) for item in value):
        raise QualificationError(f"{label} must be a list of objects")
    return value


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or not value.isascii():
        raise QualificationError(f"{label} must be nonempty ASCII text")
    return value


def _native_text(value: Any, label: str) -> str:
    if type(value) is not str:
        raise QualificationError(f"{label} must be native nonempty ASCII text")
    return _text(value, label)


def _native_text_list(value: Any, label: str) -> list[str]:
    if type(value) is not list:
        raise QualificationError(f"{label} must be a native list of nonempty ASCII text")
    return [_native_text(item, f"{label}[{index}]") for index, item in enumerate(value)]


@dataclass(frozen=True)
class OfflineReferenceAdapter:
    """Shared execution shell with no network, filesystem, process, or credential hooks."""

    manifest: AdapterManifest
    analyzer: Callable[[Mapping[str, Any]], tuple[list[dict[str, Any]], str, tuple[str, ...]]]

    def execute(self, invocation: AdapterInvocation) -> AdapterResult:
        validate_reference_invocation(self.manifest, invocation)
        try:
            observations, restoration_status, residual_effects = self.analyzer(
                invocation.input_data
            )
        except QualificationError as exc:
            evidence = AdapterEvidence.from_content(
                f"{invocation.invocation_id}.rejection",
                {"reason": str(exc), "input_accepted": False},
            )
            return AdapterResult.build(
                status="failed_closed",
                disposition="abstention",
                observations=(),
                evidence=(evidence,),
                restoration_status="failed_closed",
            )
        findings = [item for item in observations if item.get("kind") == "verified_finding"]
        disposition = "verified_finding" if findings else "negative_result"
        evidence = AdapterEvidence.from_content(
            f"{invocation.invocation_id}.analysis",
            {
                "adapter_id": self.manifest.adapter_id,
                "profile_id": self.manifest.profile_id,
                "vector_id": self.manifest.vector_id,
                "observations": observations,
                "restoration_status": restoration_status,
                "residual_effects": list(residual_effects),
            },
        )
        return AdapterResult.build(
            status="completed" if restoration_status != "failed_closed" else "failed_closed",
            disposition=disposition if restoration_status != "failed_closed" else "abstention",
            observations=tuple(observations),
            evidence=(evidence,),
            restoration_status=restoration_status,
            residual_effects=residual_effects,
        )


def analyze_passive_assets(
    data: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], str, tuple[str, ...]]:
    assets = _list_of_mappings(data.get("assets"), "assets")
    observations: list[dict[str, Any]] = []
    seen: dict[str, tuple[str, str]] = {}
    for index, asset in enumerate(assets):
        asset_id = _text(asset.get("asset_id"), f"assets[{index}].asset_id")
        source_id = _text(asset.get("source_id"), f"assets[{index}].source_id")
        fingerprint = _text(asset.get("fingerprint"), f"assets[{index}].fingerprint")
        prior = seen.get(fingerprint)
        if prior is not None and prior[0] != asset_id:
            observations.append(
                {
                    "kind": "verified_finding",
                    "finding": "duplicate_asset_identity",
                    "asset_ids": sorted((prior[0], asset_id)),
                    "fingerprint": fingerprint,
                    "evidence_ids": sorted({prior[1], source_id}),
                }
            )
        elif prior is None:
            seen[fingerprint] = (asset_id, source_id)
    observations.append(
        {
            "kind": "inventory_summary",
            "asset_count": len(assets),
            "unique_fingerprint_count": len(seen),
        }
    )
    return observations, "not_required", ()


def analyze_api_authorization(
    data: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], str, tuple[str, ...]]:
    exchanges = _list_of_mappings(data.get("exchanges"), "exchanges")
    observations: list[dict[str, Any]] = []
    for index, exchange in enumerate(exchanges):
        evidence_id = _text(exchange.get("evidence_id"), f"exchanges[{index}].evidence_id")
        subject_id = _text(exchange.get("subject_id"), f"exchanges[{index}].subject_id")
        object_id = _text(exchange.get("object_id"), f"exchanges[{index}].object_id")
        expected = exchange.get("expected_permitted")
        status_code = exchange.get("status_code")
        if (
            not isinstance(expected, bool)
            or isinstance(status_code, bool)
            or not isinstance(status_code, int)
        ):
            raise QualificationError("API authorization exchange types are invalid")
        observed_permitted = 200 <= status_code < 400
        if observed_permitted and not expected:
            observations.append(
                {
                    "kind": "verified_finding",
                    "finding": "object_authorization_differential",
                    "subject_id": subject_id,
                    "object_id": object_id,
                    "status_code": status_code,
                    "evidence_ids": [evidence_id],
                }
            )
        else:
            observations.append(
                {
                    "kind": "negative_observation",
                    "subject_id": subject_id,
                    "object_id": object_id,
                    "authorization_matched_expectation": observed_permitted == expected,
                    "evidence_ids": [evidence_id],
                }
            )
    return observations, "not_required", ()


def _reachable_paths(
    edges: list[Mapping[str, Any]], starts: set[str], goals: set[str]
) -> list[list[str]]:
    adjacency: dict[str, list[str]] = {}
    for index, edge in enumerate(edges):
        source = _text(edge.get("source"), f"edges[{index}].source")
        target = _text(edge.get("target"), f"edges[{index}].target")
        adjacency.setdefault(source, []).append(target)
    results: list[list[str]] = []
    for start in sorted(starts):
        queue = deque([(start, [start])])
        visited = {start}
        while queue:
            node, path = queue.popleft()
            if node in goals:
                results.append(path)
            for target in sorted(adjacency.get(node, [])):
                if target not in visited:
                    visited.add(target)
                    queue.append((target, [*path, target]))
    return results


def analyze_identity_paths(
    data: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], str, tuple[str, ...]]:
    edges = _list_of_mappings(data.get("edges"), "edges")
    starts = set(_native_text_list(data.get("start_principals"), "start_principals"))
    goals = set(_native_text_list(data.get("privileged_entitlements"), "privileged_entitlements"))
    if not starts or not goals:
        raise QualificationError(
            "Identity analysis requires start principals and privileged entitlements"
        )
    paths = _reachable_paths(edges, starts, goals)
    observations = [
        {
            "kind": "verified_finding",
            "finding": "privileged_entitlement_path",
            "path": path,
        }
        for path in paths
    ]
    if not observations:
        observations.append({"kind": "negative_observation", "finding": "no_privileged_path"})
    return observations, "not_required", ()


def analyze_cloud_iam(data: Mapping[str, Any]) -> tuple[list[dict[str, Any]], str, tuple[str, ...]]:
    statements = _list_of_mappings(data.get("statements"), "statements")
    observations: list[dict[str, Any]] = []
    for index, statement in enumerate(statements):
        statement_id = _text(statement.get("statement_id"), f"statements[{index}].statement_id")
        effect = statement.get("effect")
        if type(effect) is not str or effect not in {"Allow", "Deny"}:
            raise QualificationError("Cloud IAM statement effect is invalid")
        actions = _native_text_list(statement.get("actions"), f"statements[{index}].actions")
        resources = _native_text_list(statement.get("resources"), f"statements[{index}].resources")
        broad = effect == "Allow" and "*" in actions and "*" in resources
        observations.append(
            {
                "kind": "verified_finding" if broad else "negative_observation",
                "finding": "unbounded_cloud_iam_allow" if broad else "bounded_cloud_iam_statement",
                "statement_id": statement_id,
            }
        )
    return observations, "not_required", ()


def analyze_endpoint_paths(
    data: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], str, tuple[str, ...]]:
    edges = _list_of_mappings(data.get("edges"), "edges")
    start = _native_text(data.get("start_context"), "start context")
    goals = set(_native_text_list(data.get("privileged_contexts"), "privileged_contexts"))
    if not goals:
        raise QualificationError("Endpoint analysis requires privileged contexts")
    paths = _reachable_paths(edges, {start}, goals)
    observations = [
        {
            "kind": "verified_finding",
            "finding": "endpoint_privilege_path",
            "path": path,
        }
        for path in paths
    ]
    if not observations:
        observations.append(
            {"kind": "negative_observation", "finding": "no_endpoint_privilege_path"}
        )
    return observations, "not_required", ()


def analyze_ics_segmentation(
    data: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], str, tuple[str, ...]]:
    flows = _list_of_mappings(data.get("flows"), "flows")
    allowed_pairs_raw = data.get("allowed_pairs")
    if not isinstance(allowed_pairs_raw, list):
        raise QualificationError("allowed_pairs must be a list")
    allowed_pairs = {
        (_text(item[0], "allowed source"), _text(item[1], "allowed destination"))
        for item in allowed_pairs_raw
        if isinstance(item, list) and len(item) == 2
    }
    if len(allowed_pairs) != len(allowed_pairs_raw):
        raise QualificationError("allowed_pairs contains an invalid pair")
    observations: list[dict[str, Any]] = []
    for index, flow in enumerate(flows):
        source = _text(flow.get("source_zone"), f"flows[{index}].source_zone")
        destination = _text(flow.get("destination_zone"), f"flows[{index}].destination_zone")
        if (source, destination) not in allowed_pairs:
            observations.append(
                {
                    "kind": "verified_finding",
                    "finding": "unauthorized_zone_flow",
                    "source_zone": source,
                    "destination_zone": destination,
                }
            )
    if not observations:
        observations.append(
            {"kind": "negative_observation", "finding": "segmentation_matches_policy"}
        )
    before = data.get("state_before")
    after = data.get("state_after")
    if not isinstance(before, Mapping) or not isinstance(after, Mapping):
        raise QualificationError("ICS analysis requires before and after state mappings")
    if _canonical_json(dict(before)) != _canonical_json(dict(after)):
        return observations, "failed_closed", ("synthetic_state_delta_detected",)
    return observations, "verified", ()


ANALYZERS: dict[
    str, Callable[[Mapping[str, Any]], tuple[list[dict[str, Any]], str, tuple[str, ...]]]
] = {
    "passive": analyze_passive_assets,
    "api": analyze_api_authorization,
    "identity": analyze_identity_paths,
    "cloud": analyze_cloud_iam,
    "endpoint": analyze_endpoint_paths,
    "high_consequence_restoration": analyze_ics_segmentation,
}


def build_reference_adapters(
    catalog: CandidateAdapterCatalog,
) -> dict[str, OfflineReferenceAdapter]:
    """Bind reviewed manifests to closed native implementations."""

    result: dict[str, OfflineReferenceAdapter] = {}
    for manifest in catalog.manifests:
        analyzer = ANALYZERS.get(manifest.reference_role)
        if analyzer is None:
            raise QualificationError("Adapter reference role has no implementation")
        result[manifest.profile_id] = OfflineReferenceAdapter(manifest, analyzer)
    return result


__all__ = [
    "ANALYZERS",
    "OfflineReferenceAdapter",
    "analyze_api_authorization",
    "analyze_cloud_iam",
    "analyze_endpoint_paths",
    "analyze_ics_segmentation",
    "analyze_identity_paths",
    "analyze_passive_assets",
    "build_reference_adapters",
]
